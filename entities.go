package bestore

import (
	"errors"
	"time"

	"github.com/shopspring/decimal"
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
	Amount decimal.Decimal
}

type Admin struct {
	ID           uint
	Login        string
	PasswordHash []byte
}

type ProjectStatus string

const (
	Draft             ProjectStatus = "draft"
	DraftRejected     ProjectStatus = "draftRejected"
	DraftOnModeration ProjectStatus = "draftOnModeration"
	Active            ProjectStatus = "active"
	Failed            ProjectStatus = "failed"
	Success           ProjectStatus = "success"
)

func (s ProjectStatus) String() string {
	return string(s)
}

type ProjectCategory struct {
	ID   uint   `json:"id"`
	Name string `json:"name"`
}

type Project struct {
	ID               uint            `json:"id"`
	UserID           uint            `json:"user"`
	CreatedAt        time.Time       `json:"-"`
	Status           ProjectStatus   `json:"status"`
	Goal             decimal.Decimal `json:"goal"`
	DurationDays     uint            `json:"duration"`
	CategoryID       uint            `json:"category"`
	CityID           uint            `json:"city"`
	Title            string          `json:"title"`
	ShortDescription string          `json:"shortDescription"`
	FullDescription  string          `json:"fullDescription"`
	CoverURL         string          `json:"cover"`
	VideoURL         string          `json:"video"`
	FacebookURL      string          `json:"facebook"`
	TwitterURL       string          `json:"twitter"`
	Raised           decimal.Decimal `json:"raised" gorm:"-"`
	RaisedDate       time.Time       `json:"raisedDate" gorm:"-"`
	EarnBestMiner    decimal.Decimal `json:"earnBestMiner" gorm:"-"`
	IsMiningOpen     bool            `json:"isMiningOpen" gorm:"-"`
}

type ProjectBalance struct {
	ProjectID   uint
	ProjectName string
	Coins       []CoinAmount
}

type User struct {
	ID                     uint       `json:"id"`
	ExternalID             string     `json:"-"`
	CreatedAt              time.Time  `json:"-"`
	UpdatedAt              time.Time  `json:"-"`
	DeletedAt              *time.Time `json:"-"`
	Email                  string     `json:"-"`
	EmailConfirmed         bool       `json:"-"`
	PasswordHash           []byte     `json:"-"`
	Name                   string     `json:"name"`
	About                  string     `json:"about"`
	AvatarURL              string     `json:"avatar"`
	MiningProjectID        uint       `json:"-"`
	MiningProjectUpdatedAt time.Time  `json:"-"`
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

type UserMiningProject struct {
	UserID    uint
	ProjectID uint
	UpdatedAt time.Time
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

type Country struct {
	ID   uint   `json:"id"`
	Name string `json:"name"`
}

type City struct {
	ID        uint   `json:"id"`
	CountryID uint   `json:"country"`
	Name      string `json:"name"`
}
