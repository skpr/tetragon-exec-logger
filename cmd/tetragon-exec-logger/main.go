package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/christgf/env"
	tetragon "github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/skpr/tetragon-exec-logger/internal/rules"
)

// Options for the command
type Options struct {
	Addr           string
	ConfigFile     string
	ConnectTimeout time.Duration
}

// waitForAddr blocks until the TCP addr is reachable or ctx is done.
func waitForAddr(ctx context.Context, addr string, interval time.Duration) error {
	d := net.Dialer{}
	t := time.NewTicker(interval)
	defer t.Stop()

	for {
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = conn.Close()
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			// retry
		}
	}
}

// waitForGRPCReady blocks until the gRPC connection reaches READY or ctx is done.
func waitForGRPCReady(ctx context.Context, conn *grpc.ClientConn) error {
	// Ensure dialing begins.
	conn.Connect()

	for {
		st := conn.GetState()
		if st == connectivity.Ready {
			return nil
		}

		// Wait for any state change; returns false if ctx is done.
		if !conn.WaitForStateChange(ctx, st) {
			return ctx.Err()
		}
	}
}

func main() {
	o := &Options{}

	cmd := &cobra.Command{
		Use:   "tetragon-exec-logger",
		Short: "Run the Tetragon Exec Logger",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
				Level: slog.LevelInfo,
			}))

			ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer cancel()

			waitCtx, waitCancel := context.WithTimeout(ctx, o.ConnectTimeout)
			defer waitCancel()

			logger.Info("Waiting for addr to be reachable", "addr", o.Addr, "timeout", o.ConnectTimeout)

			if err := waitForAddr(waitCtx, o.Addr, 500*time.Millisecond); err != nil {
				return fmt.Errorf("addr %q not reachable within %s: %w", o.Addr, o.ConnectTimeout, err)
			}

			opts := []grpc.DialOption{
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithIdleTimeout(10 * time.Second),
			}

			conn, err := grpc.NewClient(o.Addr, opts...)
			if err != nil {
				log.Fatalf("dial %q: %v", o.Addr, err)
			}
			defer func() {
				if err := conn.Close(); err != nil {
					logger.Error("failed to close gRPC connection", "error", err)
				}
			}()

			logger.Info("Waiting for gRPC connection to become ready", "addr", o.Addr, "timeout", o.ConnectTimeout)

			if err := waitForGRPCReady(waitCtx, conn); err != nil {
				return fmt.Errorf("gRPC connection to %q not ready within %s: %w", o.Addr, o.ConnectTimeout, err)
			}

			logger.Info("Connected to Tetragon", "addr", o.Addr)

			client := tetragon.NewFineGuidanceSensorsClient(conn)

			req := &tetragon.GetEventsRequest{
				AllowList: []*tetragon.Filter{
					{
						EventSet: []tetragon.EventType{
							tetragon.EventType_PROCESS_EXEC,
						},
					},
				},
			}

			stream, err := client.GetEvents(ctx, req)
			if err != nil {
				return fmt.Errorf("failed to get event stream: %w", err)
			}

			config, err := rules.LoadConfigFromFile(o.ConfigFile)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			for {
				ev, err := stream.Recv()
				if err == io.EOF {
					logger.Info("stream closed by server")
					return nil
				}

				if err != nil {
					select {
					case <-ctx.Done():
						logger.Info("stopping", "error", ctx.Err())
						return nil
					default:
					}

					logger.Error("stream recv", "error", err)
					continue
				}

				pe := ev.GetProcessExec()
				if pe == nil {
					continue
				}

				if !config.Rules.MatchProcessExec(pe) {
					continue
				}

				logEvent := LogEvent{
					Timestamp: ev.GetTime().AsTime(),
					Node:      ev.GetNodeName(),
					Namespace: pe.GetProcess().GetPod().GetNamespace(),
					Pod:       pe.GetProcess().GetPod().GetName(),
					Container: pe.GetProcess().GetPod().GetContainer().GetName(),
					Binary:    pe.GetProcess().GetBinary(),
					Arguments: fmt.Sprintf("%v", pe.GetProcess().GetArguments()),
				}

				b, err := json.Marshal(&logEvent)
				if err != nil {
					logger.Error("failed to marshal event", "error", err)
					continue
				}

				fmt.Println(string(b))
			}
		},
	}

	cmd.PersistentFlags().StringVar(&o.Addr, "addr", env.String("SKPR_TETRAGON_EXEC_LOGGER_ADDR", "127.0.0.1:54321"), "Tetragon gRPC address host:port")
	cmd.PersistentFlags().StringVar(&o.ConfigFile, "config-file", env.String("SKPR_TETRAGON_EXEC_LOGGER_CONFIG_FILE", "/etc/tetragon-exec-logger/config.yaml"), "Path to the config file")
	cmd.PersistentFlags().DurationVar(&o.ConnectTimeout, "connect-timeout", 30*time.Second, "Max time to wait for addr to open and gRPC to become ready")

	if err := cmd.Execute(); err != nil {
		panic(err)
	}
}

// LogEvent represents a process exec event to be logged for aggregation
type LogEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Node      string    `json:"node"`
	Namespace string    `json:"namespace"`
	Pod       string    `json:"pod"`
	Container string    `json:"container"`
	Binary    string    `json:"binary"`
	Arguments string    `json:"arguments"`
}
