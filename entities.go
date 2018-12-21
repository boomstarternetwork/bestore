package bestore

import (
	"errors"
	"time"
)

type Coin string

const (
	BTC Coin = "BTC"
	ETH Coin = "ETH"
)

func ParseCoin(s string) (Coin, error) {
	switch s {
	case string(BTC):
		return BTC, nil
	case string(ETH):
		return ETH, nil
	}
	return Coin(""), errors.New("invalid or unknown coin")
}

type CoinAmount struct {
	Coin   Coin
	Amount string
}

type Admin struct {
	ID           uint64
	Login        string
	PasswordHash []byte
}

type Project struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type ProjectBalance struct {
	ProjectID   string
	ProjectName string
	Coins       []CoinAmount
}

type User struct {
	ID             uint64
	ExternalID     string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	DeletedAt      *time.Time
	Email          string
	EmailConfirmed bool
	PasswordHash   []byte
	Name           string
	AvatarURL      string
}

type UserPasswordReset struct {
	UserID    uint
	Code      string
	CreatedAt time.Time
}

type UserEmailConfirmation struct {
	UserID uint
	Code   string
	Email  string
}

type UserAddress struct {
	UserID  uint64
	Coin    string
	Address string
}

type UserBalance struct {
	Email string
	Coins []CoinAmount
}
