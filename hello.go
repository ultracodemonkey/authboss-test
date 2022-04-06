package main

import "fmt"
import (
	"context"
	"encoding/base64"
	"net/http"
	"flag"
	"time"

	"github.com/go-chi/chi/v5"
//	"github.com/go-chi/chi/v5/middleware"

	"github.com/gorilla/sessions"
	"github.com/justinas/nosurf"

	"github.com/volatiletech/authboss/v3"
	_ "github.com/volatiletech/authboss/v3/auth"
	"github.com/volatiletech/authboss/v3/confirm"
	"github.com/volatiletech/authboss/v3/defaults"
	"github.com/volatiletech/authboss/v3/lock"
	_ "github.com/volatiletech/authboss/v3/logout"
	"github.com/volatiletech/authboss-clientstate"
	"github.com/volatiletech/authboss-renderer"
	_ "github.com/volatiletech/authboss/v3/recover"
	_ "github.com/volatiletech/authboss/v3/register"
	"github.com/volatiletech/authboss/v3/remember"
)

func getRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(`welcome <a href="/auth/login">login</A> <a href="/auth/logout">logout</a> <a href="/auth/register">register</a> <a href="/private">private</a> `))
}

func getPrivate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte("secrets"))
}

var (
	flagDebug    = flag.Bool("debug", false, "output debugging information")
	flagDebugDB  = flag.Bool("debugdb", false, "output database on each request")
	flagDebugCTX = flag.Bool("debugctx", false, "output specific authboss related context keys on each request")
	flagAPI      = flag.Bool("api", false, "configure the app to be an api instead of an html app")
)

var (
	ab        = authboss.New()
	database  = NewMemStorer()
//	schemaDec = schema.NewDecoder()

	sessionStore abclientstate.SessionStorer
	cookieStore  abclientstate.CookieStorer

//	templates tpl.Templates
)

const (
	sessionCookieName = "ab_hello"
)

// layoutData is passing pointers to pointers be able to edit the current pointer
// to the request. This is still safe as it still creates a new request and doesn't
// modify the old one, it just modifies what we're pointing to in our methods so
// we're able to skip returning an *http.Request everywhere
func layoutData(w http.ResponseWriter, r **http.Request) authboss.HTMLData {
	currentUserName := ""
	userInter, err := ab.LoadCurrentUser(r)
	if userInter != nil && err == nil {
		currentUserName = userInter.(*User).Name
	}

	return authboss.HTMLData{
		"loggedin":          userInter != nil,
		"current_user_name": currentUserName,
		"csrf_token":        nosurf.Token(*r),
		"flash_success":     authboss.FlashSuccess(w, *r),
		"flash_error":       authboss.FlashError(w, *r),
	}
}

func dataInjector(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := layoutData(w, &r)
		r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyData, data))
		handler.ServeHTTP(w, r)
	})
}

func main() {
	flag.Parse()

	fmt.Println("Hello, World 6!")

	if !*flagAPI {
		// Prevent us from having to use Javascript in our basic HTML
		// to create a delete method, but don't override this default for the API
		// version
		ab.Config.Modules.LogoutMethod = "GET"
	}

	cookieStoreKey, _ := base64.StdEncoding.DecodeString(`yYql7721umGLk/Q10E9M92zNl5WDpFE0yQP4KDo5xhQtAyykWKVckIsHLqx2iPHJSHLz4QHLCwoSDLVhIzcJRg==`)
	sessionStoreKey, _ := base64.StdEncoding.DecodeString(`4DuexvT9AMyK9QcYeVo3MsOq+k8roanWE3nJqByw8ybWVzXEdXmgGAlYyUmDS4TB4ELHcnu1VKpH0FS6vDJVEg==`)
	cookieStore = abclientstate.NewCookieStorer(cookieStoreKey, nil)
	cookieStore.HTTPOnly = false
	cookieStore.Secure = false
	sessionStore = abclientstate.NewSessionStorer(sessionCookieName, sessionStoreKey, nil)
	cstore := sessionStore.Store.(*sessions.CookieStore)
	cstore.Options.HttpOnly = false
	cstore.Options.Secure = false
	cstore.MaxAge(int((30 * 24 * time.Hour) / time.Second))

	ab.Config.Storage.Server = database
	ab.Config.Storage.SessionState = sessionStore
	ab.Config.Storage.CookieState = cookieStore

	ab.Config.Paths.Mount = "/auth"
	ab.Config.Paths.RootURL = "http://localhost:4000"

	// This is using the renderer from: github.com/volatiletech/authboss
	if *flagAPI {
		ab.Config.Core.ViewRenderer = defaults.JSONRenderer{}
	} else {
		ab.Config.Core.ViewRenderer = abrenderer.NewHTML("/auth", "ab_views")
	}
	// Probably want a MailRenderer here too.
	ab.Config.Core.MailRenderer = abrenderer.NewEmail("/auth", "ab_views")

	// This instantiates and uses every default implementation
	// in the Config.Core area that exist in the defaults package.
	// Just a convenient helper if you don't want to do anything fancy.
	defaults.SetCore(&ab.Config, *flagAPI, false)

	if err := ab.Init(); err != nil {
    	    panic(err)
	}

	mux := chi.NewRouter()

//	mux.Use(middleware.Logger)

	// The middlewares we're using:
	// - logger just does basic logging of requests and debug info
	// - nosurfing is a more verbose wrapper around csrf handling
	// - LoadClientStateMiddleware is required for session/cookie stuff
	// - remember middleware logs users in if they have a remember token
	// - dataInjector is for putting data into the request context we need for our template layout
	mux.Use(logger, nosurfing, ab.LoadClientStateMiddleware, remember.Middleware(ab), dataInjector)

	// Authed routes
	mux.Group(func(mux chi.Router) {
		mux.Use(authboss.Middleware2(ab, authboss.RequireNone, authboss.RespondUnauthorized), lock.Middleware(ab), confirm.Middleware(ab))
		mux.Get("/private", getPrivate)
	})

	// Mount the router to a path (this should be the same as the Mount path above)
	// mux in this example is a chi router, but it could be anything that can route to
	// the Core.Router.
	mux.Group(func(mux chi.Router) {
		mux.Use(authboss.ModuleListMiddleware(ab))
		mux.Mount("/auth", http.StripPrefix("/auth", ab.Config.Core.Router))
	})

	mux.Get("/", getRoot)

	http.ListenAndServe(":4000", mux)
}
