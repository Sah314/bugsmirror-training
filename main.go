package main

import (
	"fmt"
	"net/http"
	"training/variables"
)

func main() {

	http.HandleFunc("/login", login)
	http.HandleFunc("/register", register)
	http.HandleFunc("/viewProfile", EditUser)
	http.HandleFunc("/getAllSongsOfPlaylist", Addsongs)
	http.HandleFunc("/createPlaylist",createPlaylist )
	//http.HandleFunc("/getAllSongsOfPlaylist", AddUser)
	//http.HandleFunc("/getAllSongsOfPlaylist", AddUser)
	}
}
