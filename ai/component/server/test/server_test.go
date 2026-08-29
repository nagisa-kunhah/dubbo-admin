package servertest

import (
	"strings"
	"testing"

	compServer "dubbo-admin-ai/component/server"
)

func TestServerComponent_Validate(t *testing.T) {
	tests := []struct {
		name         string
		port         int
		readTimeout  int
		writeTimeout int
		errContain   string
	}{
		{name: "port_range", port: 70000, readTimeout: 30, writeTimeout: 30, errContain: "port"},
		{name: "read_timeout_positive", port: 8080, readTimeout: 0, writeTimeout: 30, errContain: "timeout"},
		{name: "write_timeout_positive", port: 8080, readTimeout: 30, writeTimeout: 0, errContain: "timeout"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			comp, err := compServer.NewServerComponent(tt.port, "0.0.0.0", false, []string{"*"}, tt.readTimeout, tt.writeTimeout)
			if err != nil {
				t.Fatalf("NewServerComponent() error: %v", err)
			}
			if err := comp.Validate(); err == nil || !strings.Contains(err.Error(), tt.errContain) {
				t.Fatalf("expected %q validation error, got %v", tt.errContain, err)
			}
		})
	}
}

func TestServerComponent_ValidateAuth(t *testing.T) {
	tests := []struct {
		name string
		auth compServer.AuthSpec
		want string
	}{
		{name: "disabled by default", auth: compServer.AuthSpec{}},
		{name: "missing jwks", auth: compServer.AuthSpec{Enabled: true, Issuer: "dubbo-admin", Audience: "dubbo-admin-ai"}, want: "jwks_url"},
		{name: "invalid jwks", auth: compServer.AuthSpec{Enabled: true, JWKSURL: "://bad", Issuer: "dubbo-admin", Audience: "dubbo-admin-ai"}, want: "jwks_url"},
		{name: "missing issuer", auth: compServer.AuthSpec{Enabled: true, JWKSURL: "https://admin.example/jwks", Audience: "dubbo-admin-ai"}, want: "issuer"},
		{name: "missing audience", auth: compServer.AuthSpec{Enabled: true, JWKSURL: "https://admin.example/jwks", Issuer: "dubbo-admin"}, want: "audience"},
		{name: "valid", auth: compServer.AuthSpec{Enabled: true, JWKSURL: "https://admin.example/jwks", Issuer: "dubbo-admin", Audience: "dubbo-admin-ai"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			component, err := compServer.NewServerComponentWithAuth(8080, "0.0.0.0", false, []string{"*"}, 30, 30, tt.auth)
			if err != nil {
				t.Fatal(err)
			}
			err = component.Validate()
			if tt.want == "" && err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)) {
				t.Fatalf("Validate() error = %v, want containing %q", err, tt.want)
			}
		})
	}
}
