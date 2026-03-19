package service

import (
	"context"
	"log"
	"net"
	"os"
	"testing"

	"github.com/peterouob/block_chain/node/rpc"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

var testAccountClient rpc.AccountClient

func TestMain(m *testing.M) {
	tmpDir, _ := os.MkdirTemp("", "keystore-test-*")

	lis := bufconn.Listen(1024 * 1024)
	s := grpc.NewServer()
	rpc.RegisterAccountServer(s, &AccountService{
		KeyStorePath: tmpDir,
	})

	go func() {
		if err := s.Serve(lis); err != nil {
			log.Fatalf("Server exited with error: %v", err)
		}
	}()

	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		return lis.Dial()
	}

	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)

	if err != nil {
		log.Fatalf("failed to dial bufnet: %v", err)
	}

	testAccountClient = rpc.NewAccountClient(conn)

	code := m.Run()

	conn.Close()
	s.Stop()
	os.RemoveAll(tmpDir)

	os.Exit(code)
}

func TestAccountService_AccountCreate(t *testing.T) {
	t.Run("success create account", func(t *testing.T) {
		req := &rpc.AccountRequest{Pass: "super_secret"}

		res, err := testAccountClient.AccountCreate(context.Background(), req)

		assert.NoError(t, err)
		assert.NotEmpty(t, res.Address)
	})

	t.Run("password too short", func(t *testing.T) {
		req := &rpc.AccountRequest{Pass: "123"}

		res, err := testAccountClient.AccountCreate(context.Background(), req)

		assert.Error(t, err)
		assert.Nil(t, res)
	})
}
