package bestore

import (
	"time"

	"github.com/shopspring/decimal"
)

type User struct {
	ID             uint       `json:"id,string"`
	ExternalID     string     `json:"-"`
	CreatedAt      time.Time  `json:"-"`
	UpdatedAt      time.Time  `json:"-"`
	DeletedAt      *time.Time `json:"-"`
	Email          string     `json:"-"`
	EmailConfirmed bool       `json:"-"`
	PasswordHash   []byte     `json:"-"`
	Name           string     `json:"name"`
	AvatarURL      string     `json:"avatar"`
	EthAddress     string     `json:"-"`
}

type ProjectCategory struct {
	ID   uint   `json:"id,string"`
	Name string `json:"name"`
}

type Country struct {
	ID   uint   `json:"id,string"`
	Name string `json:"name"`
}

type City struct {
	ID        uint   `json:"id,string"`
	CountryID uint   `json:"country"`
	Name      string `json:"name"`
}

type OperationStatus string

var (
	InitOS    OperationStatus = "init"
	WIPOS     OperationStatus = "wip"
	SuccessOS OperationStatus = "success"
	FailureOS OperationStatus = "failure"
)

func (s OperationStatus) String() string {
	return string(s)
}

type ProjectStatus string

const (
	DraftPS   ProjectStatus = "draft"
	ActivePS  ProjectStatus = "active"
	SuccessPS ProjectStatus = "success"
	FailurePS ProjectStatus = "failed"
)

func (s ProjectStatus) String() string {
	return string(s)
}

type Project struct {
	ID                      uint            `json:"id,string"`
	UserID                  uint            `json:"user,string"`
	CreatedAt               time.Time       `json:"-"`
	Status                  ProjectStatus   `json:"status"`
	ModerationStatus        OperationStatus `json:"moderationStatus"`
	ModerationRejectMessage string          `json:"moderationRejectStatus"`
	Goal                    decimal.Decimal `json:"goal"`
	DurationDays            uint            `json:"duration"`
	CategoryID              uint            `json:"category"`
	CityID                  uint            `json:"city"`
	Title                   string          `json:"title"`
	ShortDescription        string          `json:"shortDescription"`
	FullDescription         string          `json:"fullDescription"`
	CoverURL                string          `json:"cover"`
	VideoURL                string          `json:"video"`
	FacebookURL             string          `json:"facebook"`
	TwitterURL              string          `json:"twitter"`
	EthAddress              string          `json:"-"`
	Raised                  decimal.Decimal `json:"raised" gorm:"-"`
	RaisedDate              time.Time       `json:"raisedDate" gorm:"-"`
	EarnBestMiner           decimal.Decimal `json:"earnBestMiner" gorm:"-"`
	IsMiningOpen            bool            `json:"isMiningOpen" gorm:"-"`
}

type UserPasswordReset struct {
	UserID    uint
	CreatedAt time.Time
	Code      string
}

type UserEmailConfirmation struct {
	UserID uint
	Code   string
	Email  string
}

type UserKYC struct {
	UserID             uint `json:"-"`
	EthAddress         string
	FullName           string
	DateOfBirth        string
	PlaceOfBirth       string
	PlaceOfResidence   string
	CountryOfResidence string
	Phone              string
	Doc1FileName       string          `json:"-"`
	Doc2FileName       string          `json:"-"`
	Status             OperationStatus `json:"-"`
	FailureMessage     string          `json:"-"`
}

func (UserKYC) TableName() string {
	return "user_kycs"
}

type UserMiningCredential struct {
	UserID       uint
	Login        string
	PasswordHash []byte
}

type UserMiningProject struct {
	UserID    uint
	ProjectID uint
	UpdatedAt time.Time
}

type UserWithdraw struct {
	UserID uint
	Status OperationStatus
	Amount decimal.Decimal
}

type Balance struct {
	ProjectID uint   `gorm:"column:projectid"`
	PoolID    string `gorm:"column:poolid"`
	Address   string
	Amount    decimal.Decimal
	Created   time.Time
	Updated   time.Time
}
