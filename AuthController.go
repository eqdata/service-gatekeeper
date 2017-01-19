package main

import (
	"net/http"
	"fmt"
	"github.com/bradfitz/gomemcache/memcache"
	"strings"
)

type AuthController struct {
	Controller
}

func (c *AuthController) authorise(w http.ResponseWriter, r *http.Request) {

	var apiKey string = r.Header.Get("apiKey")
	var email string = r.Header.Get("email")

	// check for invalid credentials
	if len(strings.TrimSpace(apiKey)) < 14 || len(strings.TrimSpace(email)) == 5 {
		if apiKey == "" { apiKey = "nil" }
		if email == "" { email = "nil" }

		fmt.Println("Invalid tokens")
		http.Error(w, "Please ensure you send a valid API Token and Email. You provided email: " + email + ", API Key: " + apiKey, 401)
		return
	}

	// Authorise request
	var user User
	user.APIKey = apiKey
	user.Email = email
	user.Requests = 0
	user.ValidAPIKey = false
	user.SetLockedTimestamp = false

	fmt.Println("Authorising for user: " + user.APIKey + " " + user.Email)
	valid, message := c.isClientAppAuthorised(user)
	if valid {
		fmt.Println("User is authed")
		http.Error(w, message, 200)
	} else {
		fmt.Println("User is not authed")
		http.Error(w, message, 401)
	}
}

// Go to the memcache server and see if this combination has already exceeded the limit
// of requests in the time-frame
func (c *AuthController) isClientAppAuthorised(user User) (bool, string) {

	// Check memcached to see if we already have this email address stored
	mc := memcache.New(MC_HOST + ":" + MC_PORT)

	// Use an _ as we don't need to use the cache item returned
	key := strings.TrimSpace("email:" + user.Email)
	mcObj, err := mc.Get(key)
	if err != nil {
		if err.Error() == "memcache: cache miss" {
			// Validate the users API key
			user.Requests += 1

			fmt.Println("Setting email: " + key + " in cache for: " + fmt.Sprint(CACHE_TIME_IN_SECS) + " seconds")
			mc.Set(&memcache.Item{Key: key, Value: user.serialize(), Expiration: CACHE_TIME_IN_SECS})

			if c.isValidAPIKey(user.APIKey, user.Email) {
				user.ValidAPIKey = true
				return true, "Added user: " + user.Email + " to memcached with key: " + user.APIKey + " they have " + fmt.Sprint(user.Requests) + "/" + fmt.Sprint(MAX_REQUESTS_BEFORE_LOCKOUT) + " requests remaining for the next 3 minutes"
			} else {
				return false, "User: " + user.APIKey + " provided an invalid combination of email/api key. They have been placed back into the cache for: " + fmt.Sprint(CACHE_TIME_IN_SECS) + " seconds and will be locked out after " + fmt.Sprint(MAX_INVALID_API_KEY_ATTEMPTS - user.Requests) + " more failed attempts"
			}
		} else {
			fmt.Println("Error was: ", err.Error())
			return false, ("MC Error: " + err.Error())
		}
	} else {
		newAPIKey := user.APIKey
		user = user.deserialize(mcObj.Value)
		expiresAt := mcObj.Expiration

		user.Requests += 1

		if !user.ValidAPIKey && !c.isValidAPIKey(user.APIKey, user.Email) {
			if user.Requests > MAX_INVALID_API_KEY_ATTEMPTS {
				expires := expiresAt
				if !user.SetLockedTimestamp {
					expires = CACHE_LOCKOUT_TIME_IN_SECS/2
				} else {
					user.SetLockedTimestamp = true
				}
				mc.Set(&memcache.Item{Key: key, Value: user.serialize(), Expiration: (expires)})
				return false, "User: " + user.Email + " with key: " + user.APIKey + " has reached maximum invalid API key requests: " + fmt.Sprint(MAX_INVALID_API_KEY_ATTEMPTS) + ", within the time-frame.  They are now locked out for " + fmt.Sprint(expires / 2) + " seconds"
			} else if user.Requests > 0 {
				expires := expiresAt
				if !user.SetLockedTimestamp {
					expires = CACHE_TIME_IN_SECS
				} else {
					user.SetLockedTimestamp = true
				}
				mc.Replace(&memcache.Item{Key: key, Value: user.serialize(), Expiration: expires})
				return false, "User: " + user.APIKey + " provided an invalid combination of email/api key. They have been placed back into the cache for: " + fmt.Sprint(expires) + " seconds and will be locked out after " + fmt.Sprint(MAX_INVALID_API_KEY_ATTEMPTS - user.Requests + 1) + " more failed attempts"
			}
		}

		user.ValidAPIKey = true

		fmt.Println("Checking if: " + newAPIKey + " is equal to: " + user.APIKey)
		if newAPIKey != user.APIKey {
			if !c.isValidAPIKey(newAPIKey, user.Email) {
				fmt.Println("It wasnt valid either")
				user.ValidAPIKey = false
				expires := expiresAt
				if !user.SetLockedTimestamp {
					expires = CACHE_TIME_IN_SECS
				} else {
					user.SetLockedTimestamp = true
				}
				mc.Replace(&memcache.Item{Key: key, Value: user.serialize(), Expiration: expires})
				return false, "User: " + user.APIKey + " provided an invalid combination of email/api key. They have been placed back into the cache for: " + fmt.Sprint(expires) + " seconds and will be locked out after " + fmt.Sprint(MAX_INVALID_API_KEY_ATTEMPTS - user.Requests + 1) + " more failed attempts"
			} else {
				user.ValidAPIKey = true
			}
		}

		if (user.Requests) > MAX_REQUESTS_BEFORE_LOCKOUT {
			expires := expiresAt
			if !user.SetLockedTimestamp {
				expires = CACHE_LOCKOUT_TIME_IN_SECS
			} else {
				user.SetLockedTimestamp = true
			}
			mc.Set(&memcache.Item{Key: key, Value: user.serialize(), Expiration: expires})
			return false, "User: " + user.Email + " with key: " + user.APIKey + " has reached maximum requests of " + fmt.Sprint(MAX_REQUESTS_BEFORE_LOCKOUT) + ", within the time-frame.  They are now locked out for " + fmt.Sprint(expires) + " seconds"
		}

		user.SetLockedTimestamp = false
		mc.Replace(&memcache.Item{Key: key, Value: user.serialize(), Expiration: expiresAt})
		return true, "Incremented user: " + user.Email + " with key: " + user.APIKey + " attempts to: " + fmt.Sprint(user.Requests) + ", there are " + fmt.Sprint(expiresAt) + " seconds left until this cache entry expires."
	}
}

func (c *AuthController) isValidAPIKey(apiKey string, email string) bool {
	found := false

	query := "SELECT email FROM users WHERE apiKey = ? AND email = ?"
	rows, _ := DB.Query(query, apiKey, email)
	if rows != nil {
		for rows.Next() {
			var email string
			rows.Scan(&email)

			if strings.TrimSpace(email) != "" {
				found = true
			}
		}
	}

	return found
}
