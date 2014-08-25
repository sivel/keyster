// Copyright 2014 Matt Martz <matt@sivel.net>
// All Rights Reserved.
//
//    Licensed under the Apache License, Version 2.0 (the "License"); you may
//    not use this file except in compliance with the License. You may obtain
//    a copy of the License at
//
//         http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
//    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
//    License for the specific language governing permissions and limitations
//    under the License.

package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"

	"crypto/md5"

	"html/template"

	"code.google.com/p/go.crypto/ssh"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/mholt/binding"
	"github.com/unrolled/render"
	"github.com/vanackere/ldap"
)

func KeyFingerprint(key []byte) string {
	var fingerprint []string
	h := md5.New()
	io.WriteString(h, string(key))
	hash := fmt.Sprintf("%x", h.Sum(nil))
	for i, c := range hash {
		fingerprint = append(fingerprint, string(c))
		if i != len(string(hash))-1 && i%2 == 1 {
			fingerprint = append(fingerprint, ":")
		}
	}
	return strings.Join(fingerprint, "")
}

type LoginForm struct {
	Username string
	Password string
}

func (l *LoginForm) FieldMap() binding.FieldMap {
	return binding.FieldMap{
		&l.Username: "username",
		&l.Password: "password",
	}
}

type UserForm struct {
	Keys string
}

func (u *UserForm) FieldMap() binding.FieldMap {
	return binding.FieldMap{
		&u.Keys: "keys",
	}
}

type UserKey struct {
	Id          string `bson:"_id"`
	Username    string
	Timestamp   time.Time
	Key         string
	Deactivated bool
}

func (u *UserKey) IsExpired(delta time.Duration, includeDeactivated bool) bool {
	expireTime := u.Timestamp.Add(delta)
	if (delta != 0 && expireTime.Before(time.Now().UTC())) || (includeDeactivated && u.Deactivated) {
		return true
	} else {
		return false
	}
}

type Handler struct {
	Render  *render.Render
	Mongo   *mgo.Session
	Router  *mux.Router
	Session *sessions.CookieStore
	LDAP    struct {
		Server string
		BaseDN string
		SSL    bool
	}
	Key struct {
		Duration     time.Duration
		AllowOptions bool
	}
}

func (h *Handler) GetCurrentUserKeys(username string) []string {
	mongo := h.Mongo.Copy()
	defer mongo.Close()

	c := mongo.DB("keyster").C("keys")

	var keys []UserKey
	var keysOut []string

	c.Find(bson.M{"username": username}).All(&keys)
	for _, key := range keys {
		if !key.IsExpired(h.Key.Duration, true) {
			keysOut = append(keysOut, key.Key)
		}
	}

	return keysOut
}

func (h *Handler) GetURL(name string, params ...interface{}) string {
	var vars []string
	for _, param := range params {
		v, ok := param.(string)
		if !ok {
			return "#error"
		}
		vars = append(vars, v)
	}
	url, _ := h.Router.Get(name).URL(vars...)
	return url.String()
}

func (h *Handler) GetFlashes(w http.ResponseWriter, req *http.Request) map[string][]interface{} {
	types := []string{"danger", "warning", "info", "success"}
	flashes := make(map[string][]interface{})
	session, _ := h.Session.Get(req, "session")
	for _, t := range types {
		flashes[t] = session.Flashes(t)
	}
	session.Save(req, w)
	return flashes
}

func (h *Handler) IndexHandler(w http.ResponseWriter, req *http.Request) {
	session, _ := h.Session.Get(req, "session")
	h.Render.HTML(w, http.StatusOK, "index", map[string]interface{}{"Session": session, "Flashes": h.GetFlashes(w, req)})
}

func (h *Handler) LoginHandler(w http.ResponseWriter, req *http.Request) {
	session, _ := h.Session.Get(req, "session")

	username, ok := session.Values["username"].(string)
	if ok {
		url, _ := h.Router.Get("user").URL("username", username)
		http.Redirect(w, req, url.String(), 302)
		return
	}
	context := map[string]interface{}{
		"Page":    "Log In",
		"Session": session,
		"Flashes": h.GetFlashes(w, req),
	}
	h.Render.HTML(w, http.StatusOK, "login", context)
	return
}

func (h *Handler) LoginPostHandler(w http.ResponseWriter, req *http.Request) {
	var l *ldap.Conn
	var err error
	session, _ := h.Session.Get(req, "session")

	loginForm := new(LoginForm)
	binding.Bind(req, loginForm)

	loginURL, _ := h.Router.Get("login").URL()

	if h.LDAP.SSL {
		l, err = ldap.DialTLS("tcp", h.LDAP.Server, nil)
	} else {
		l, err = ldap.Dial("tcp", h.LDAP.Server)
	}
	if err != nil {
		session.AddFlash("Failure communicating with LDAP server", "danger")
		session.Save(req, w)
		http.Redirect(w, req, loginURL.String(), 301)
		return
	}
	defer l.Close()
	err = l.Bind(fmt.Sprintf("cn=%s,%s", loginForm.Username, h.LDAP.BaseDN), loginForm.Password)
	if err != nil {
		session.AddFlash("Log In Failure", "danger")
		session.Save(req, w)
		http.Redirect(w, req, loginURL.String(), 301)
		return
	}
	session.Values["username"] = loginForm.Username
	session.Save(req, w)

	queryVars := req.URL.Query()
	if len(queryVars["next"]) == 1 {
		http.Redirect(w, req, queryVars["next"][0], 302)
	} else {
		url, _ := h.Router.Get("user").URL("username", loginForm.Username)
		http.Redirect(w, req, url.String(), 301)
	}
	return
}

func (h *Handler) UserKeysHandler(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	keysOut := h.GetCurrentUserKeys(vars["username"])
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(fmt.Sprintf("%s\n", strings.Join(keysOut, "\n"))))
}

func (h *Handler) UserHandler(w http.ResponseWriter, req *http.Request) {
	var readOnly bool = false

	vars := mux.Vars(req)
	session, _ := h.Session.Get(req, "session")
	username, ok := session.Values["username"].(string)
	if !ok {
		loginURL, _ := h.Router.Get("login").URL()
		loginURL.RawQuery = fmt.Sprintf("next=%s", url.QueryEscape(req.RequestURI))
		http.Redirect(w, req, loginURL.String(), 302)
		return
	}
	reqUsername := vars["username"]
	/*if ctx.Session.Get("admin") != true && username != ctx.Session.Get("username") {
		ctx.r.Redirect(fmt.Sprintf("/user/%s", ctx.Session.Get("username")))
	}*/
	if reqUsername != username {
		readOnly = true
		username = reqUsername
	}

	keysOut := h.GetCurrentUserKeys(username)

	context := map[string]interface{}{
		"Session":  session,
		"Flashes":  h.GetFlashes(w, req),
		"Keys":     strings.Join(keysOut, "\n"),
		"ReadOnly": readOnly,
		"Username": username,
	}
	if readOnly {
		context["Page"] = reqUsername
	} else {
		context["Page"] = "My Profile"
	}
	h.Render.HTML(w, http.StatusOK, "user", context)
}

func (h *Handler) UserPostHandler(w http.ResponseWriter, req *http.Request) {
	var fingerprint string
	var current []string
	var key UserKey
	//vars := mux.Vars(req)

	userForm := new(UserForm)
	binding.Bind(req, userForm)

	session, _ := h.Session.Get(req, "session")
	username, ok := session.Values["username"].(string)
	if !ok {
		loginURL, _ := h.Router.Get("login").URL()
		loginURL.RawQuery = fmt.Sprintf("next=%s", url.QueryEscape(req.RequestURI))
		http.Redirect(w, req, loginURL.String(), 302)
		return
	}

	//username := vars["username"]
	/*username := params["username"]
	if ctx.Session.Get("admin") != true && username != ctx.Session.Get("username") {
		ctx.r.Redirect(fmt.Sprintf("/user/%s", ctx.Session.Get("username")))
	}*/

	mongo := h.Mongo.Copy()
	c := mongo.DB("keyster").C("keys")
	defer mongo.Close()
	if len(userForm.Keys) > 0 {
		for _, value := range strings.Split(userForm.Keys, "\n") {
			if strings.TrimSpace(value) == "" {
				continue
			}
			out, comment, options, _, err := ssh.ParseAuthorizedKey([]byte(value))
			if err == nil {
				var keyString string
				if h.Key.AllowOptions {
					keyString = strings.TrimSpace(fmt.Sprintf("%s %s %s %s", strings.Join(options, ","), out.Type(), base64.StdEncoding.EncodeToString(out.Marshal()), comment))
				} else {
					options = make([]string, 0)
					keyString = strings.TrimSpace(fmt.Sprintf("%s %s %s", out.Type(), base64.StdEncoding.EncodeToString(out.Marshal()), comment))

				}
				fingerprint = KeyFingerprint(out.Marshal())

				err = c.Find(bson.M{"_id": fingerprint, "username": username}).One(&key)
				if err == nil && key.IsExpired(h.Key.Duration, false) {
					session.AddFlash(fmt.Sprintf("Key already used and expired: %s", fingerprint), "danger")
					continue
				} else if err == nil {
					_, testComment, testOptions, _, _ := ssh.ParseAuthorizedKey([]byte(key.Key))
					if comment != testComment || strings.Join(options, ",") != strings.Join(testOptions, ",") || key.Deactivated == true {
						err := c.Update(bson.M{"_id": fingerprint}, bson.M{
							"$set": bson.M{
								"key":         keyString,
								"deactivated": false,
							},
						})
						if err != nil {
							session.AddFlash(fmt.Sprintf("Error updating key: %s", fingerprint), "danger")
						} else {
							session.AddFlash(fmt.Sprintf("Updated key: %s", fingerprint), "success")
						}
					}
					current = append(current, fingerprint)
					continue
				}

				err := c.Insert(UserKey{
					Id:          fingerprint,
					Username:    username,
					Timestamp:   time.Now().UTC(),
					Key:         keyString,
					Deactivated: false,
				})
				if mgo.IsDup(err) {
					session.AddFlash(fmt.Sprintf("Duplicate SSH key submitted: %s", fingerprint), "warning")
				} else if err != nil {
					session.AddFlash(fmt.Sprintf("Unknown error occurred with: %s", fingerprint), "danger")
				} else {
					session.AddFlash(fmt.Sprintf("Added new key: %s", fingerprint), "success")
					current = append(current, fingerprint)
				}
			} else {
				session.AddFlash(fmt.Sprintf("Error Parsing key: %s", value), "danger")
			}
		}
	}

	var notDeactivatedUserKeys []UserKey
	if len(current) > 0 {
		c.Find(bson.M{"_id": bson.M{"$nin": current}, "username": username, "deactivated": false}).All(&notDeactivatedUserKeys)
	} else {
		c.Find(bson.M{"deactivated": false, "username": username}).All(&notDeactivatedUserKeys)
	}
	for _, key := range notDeactivatedUserKeys {
		if !key.IsExpired(h.Key.Duration, false) {
			c.Update(bson.M{"_id": key.Id}, bson.M{"$set": bson.M{"deactivated": true}})
			session.AddFlash(fmt.Sprintf("Deactivated key: %s", key.Id), "info")
		}
	}

	session.Save(req, w)
	url, _ := h.Router.Get("user").URL("username", username)
	http.Redirect(w, req, url.String(), 301)
}

func (h *Handler) LogoutHandler(w http.ResponseWriter, req *http.Request) {
	session, _ := h.Session.Get(req, "session")
	session.Options.MaxAge = -1
	sessions.Save(req, w)
	url, _ := h.Router.Get("index").URL()
	http.Redirect(w, req, url.String(), 302)
}

func main() {
	var Port string
	var Cert string
	var Key string
	var LDAPServer string
	var LDAPBaseDN string
	var LDAPSSL bool
	var KeyDuration string
	var KeyAllowOptions bool
	var LogFile string
	var logFile *os.File

	mongo, err := mgo.Dial("127.0.0.1")
	if err != nil {
		log.Fatal(err)
	}

	flag.StringVar(&Port, "port", ":3000", "HOST:PORT to listen on, HOST not required to listen on all addresses")
	flag.StringVar(&Cert, "cert", "", "SSL cert file path. This option with 'key' enables SSL communication")
	flag.StringVar(&Key, "key", "", "SSL key file path. This option with 'cert' enables SSL communication")
	flag.StringVar(&LDAPServer, "ldap-server", "", "LDAP server HOST:PORT")
	flag.StringVar(&LDAPBaseDN, "ldap-base-dn", "", "Base DN of users")
	flag.BoolVar(&LDAPSSL, "ldap-ssl", false, "Use SSL or TLS for connectivity to the LDAP server")
	flag.StringVar(&KeyDuration, "key-duration", "0", "Duration of key validity. 0 disables expiration. See http://golang.org/pkg/time/#ParseDuration")
	flag.BoolVar(&KeyAllowOptions, "key-allow-options", false, "Whether keys are allowed to contain options")
	flag.StringVar(&LogFile, "log-file", "-", "Log file path. Use - for stdout")
	flag.Parse()

	router := mux.NewRouter().StrictSlash(true)

	file, _ := os.Open("/dev/urandom")
	secret := make([]byte, 24)
	file.Read(secret)
	file.Close()

	keyDuration, err := time.ParseDuration(KeyDuration)
	if err != nil {
		log.Fatalf("%s could not be parsed as a time duration. See http://golang.org/pkg/time/#ParseDuration", KeyDuration)
	}

	h := Handler{
		Router:  router,
		Session: sessions.NewCookieStore(secret),
		Mongo:   mongo,
	}

	r := render.New(render.Options{
		Layout: "layout",
		Funcs: []template.FuncMap{
			{
				"Title":  strings.Title,
				"GetURL": h.GetURL,
			},
		},
	})

	h.Render = r
	h.LDAP.Server = LDAPServer
	h.LDAP.BaseDN = LDAPBaseDN
	h.LDAP.SSL = LDAPSSL
	h.Key.Duration = keyDuration
	h.Key.AllowOptions = KeyAllowOptions

	if LogFile == "-" {
		logFile = os.Stdout
	} else {
		absPath, err := filepath.Abs(LogFile)
		if err != nil {
			log.Fatal(err)
		}
		logFile, err = os.OpenFile(absPath, os.O_RDWR|os.O_APPEND, 0440)
		if err != nil {
			log.Fatal(err)
		}
	}
	loggingHandler := handlers.CombinedLoggingHandler(logFile, router)

	router.HandleFunc("/", h.IndexHandler).Name("index")
	router.HandleFunc("/login", h.LoginHandler).Methods("GET").Name("login")
	router.HandleFunc("/login", h.LoginPostHandler).Methods("POST")
	router.HandleFunc("/logout", h.LogoutHandler).Name("logout")

	router.HandleFunc("/users/{username}", h.UserHandler).Methods("GET").Name("user")
	router.HandleFunc("/users/{username}", h.UserPostHandler).Methods("POST")
	router.HandleFunc("/users/{username}/keys", h.UserKeysHandler).Name("userkeys")

	http.Handle("/", loggingHandler)

	if len(Cert) == 0 || len(Key) == 0 {
		log.Fatal(http.ListenAndServe(Port, loggingHandler))
	} else {
		log.Fatal(http.ListenAndServeTLS(Port, Cert, Key, loggingHandler))
	}
}
