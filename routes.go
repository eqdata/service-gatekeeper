package main

import "net/http"

type Route struct {
	name 	string
	method 	string
	pattern string
	handler http.HandlerFunc
}

type Routes []Route

// Define any application routes here
var routes = Routes {
	Route {
		"Store User",
		"POST",
		"/users",
		UC.store,
	},
	Route {
		"Authorise User",
		"GET",
		"/auth",
		AC.authorise,
	},
}