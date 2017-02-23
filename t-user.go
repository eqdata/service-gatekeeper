package main

import (
	"encoding/json"
	"fmt"
	"time"
)

type User struct {
	Email string
	APIKey string
	Requests int32
	TimesLockedOut int32
	ValidAPIKey bool
	SetLockedTimestamp bool
	ReleaseCacheAt time.Time
}

func (u *User) serialize() []byte {
	bytes, err := json.Marshal(u)
	if err != nil {
		fmt.Println("Error when marshaling: ", err)
	}

	return bytes
}

func (u *User) deserialize(bytes []byte) User {
	var user User

	err := json.Unmarshal(bytes, &user)
	if err != nil {
		fmt.Println("Error when unmarshaling: ", err)
	}

	return user
}
