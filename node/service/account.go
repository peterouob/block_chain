package service

import (
	"context"

	"github.com/peterouob/block_chain/chain"
	"github.com/peterouob/block_chain/node/rpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type BalanceChecker interface {
	Balance(address string) (uint64, bool)
}

type AccountService struct {
	rpc.UnimplementedAccountServer
	BalanceChecker BalanceChecker
	KeyStorePath   string
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

	if err := acc.Write(s.KeyStorePath, pass); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	res := &rpc.AccountResponse{
		Address: string(acc.Addr()),
	}
	return res, nil
}

func (s *AccountService) AccountBalance(_ context.Context, req *rpc.AccountBalanceReq) (*rpc.AccountBalanceRes, error) {
	acc := req.Address
	balance, exist := s.BalanceChecker.Balance(acc)
	if !exist {
		return nil, status.Errorf(
			codes.NotFound, "account %v does not exist or has not yet transacted", acc,
		)
	}

	res := &rpc.AccountBalanceRes{
		Balance: balance,
	}
	return res, nil
}
