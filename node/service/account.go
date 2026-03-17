package service

import (
	"context"

	"github.com/peterouob/block_chain/chain"
	"github.com/peterouob/block_chain/node/rpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AccountService struct {
	keyStorePath string
	rpc.UnimplementedAccountServer
}

func (s *AccountService) AccountCreate(_ context.Context, req *rpc.AccountRequest) (*rpc.AccountResponse, error) {
	pass := []byte(req.Pass)
	if len(pass) < 5 {
		return nil, status.Error(
			codes.InvalidArgument, "password length is less than 5",
		)
	}

	acc, err := chain.NewAccount()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	if err := acc.Write(s.keyStorePath, pass); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	res := &rpc.AccountResponse{
		Address: string(acc.Addr()),
	}
	return res, nil
}
