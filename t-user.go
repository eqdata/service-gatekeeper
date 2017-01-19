package main

import (
	"encoding/json"
	"fmt"
)

type User struct {
	Email string
	APIKey string
	Requests int32
	TimesLocketOut int32
	ValidAPIKey bool
	SetLockedTimestamp bool
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
