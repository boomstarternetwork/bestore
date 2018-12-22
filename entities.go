package bestore

import (
	"errors"
	"time"
)

type Coin string

func (c Coin) String() string {
	return string(c)
}

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
	ID           uint
	Login        string
	PasswordHash []byte
}

type Project struct {
	ID   uint   `json:"id"`
	Name string `json:"name"`
}

type ProjectBalance struct {
	ProjectID   uint
	ProjectName string
	Coins       []CoinAmount
}

type User struct {
	ID             uint
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
	UserID  uint
	Coin    Coin
	Address string
}

type UserBalance struct {
	Email string
	Coins []CoinAmount
}
