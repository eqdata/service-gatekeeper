package main

import (
	"net/http"
	"fmt"
	"encoding/json"
)

type UserController struct {
	Controller
}

// Stores auction data to the Amazon RDS storage once it has been parsed
func (c *UserController) store(w http.ResponseWriter, r *http.Request) {
	var items []string
	if r.Body == nil {
		http.Error(w, "Please send a request body", 400)
		return
	}
	err := json.NewDecoder(r.Body).Decode(&items)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	fmt.Println("items are: ", items)
	if len(items) == 0 {
		http.Error(w, "No lines were present in the auctions array", 400)
		return
	}
}
