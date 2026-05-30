package protocol

import (
	"encoding/json"
	"strings"

	"golang.org/x/text/language"
)

type Locales []language.Tag

func ParseLocales(tags []string) Locales {
	out := make(Locales, 0, len(tags))
	for _, s := range tags {
		tag, err := language.Parse(s)
		if err == nil && !tag.IsRoot() {
			out = append(out, tag)
		}
	}
	return out
}

func (l Locales) String() string {
	tags := make([]string, len(l))
	for i, tag := range l {
		tags[i] = tag.String()
	}
	return strings.Join(tags, " ")
}

func (l *Locales) UnmarshalText(text []byte) error {
	s := strings.TrimSpace(string(text))
	if s == "" {
		*l = nil
		return nil
	}
	*l = ParseLocales(strings.Split(s, " "))
	return nil
}

func (l Locales) MarshalText() ([]byte, error) {
	return []byte(l.String()), nil
}

func (l *Locales) UnmarshalJSON(data []byte) error {
	var dst any
	if err := json.Unmarshal(data, &dst); err != nil {
		return err
	}
	switch v := dst.(type) {
	case nil:
		*l = nil
	case string:
		*l = ParseLocales(strings.Split(v, " "))
	case []any:
		strs := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				strs = append(strs, s)
			}
		}
		*l = ParseLocales(strs)
	}
	return nil
}

type ResponseType string

type ResponseMode string

type Display string

const (
	DisplayPage  Display = "page"
	DisplayPopup Display = "popup"
	DisplayTouch Display = "touch"
	DisplayWAP   Display = "wap"
)

func (d *Display) UnmarshalText(text []byte) error {
	switch Display(text) {
	case DisplayPage, DisplayPopup, DisplayTouch, DisplayWAP:
		*d = Display(text)
	}
	return nil
}

type SpaceDelimitedArray []string

func (s SpaceDelimitedArray) String() string {
	return strings.Join(s, " ")
}

func (s *SpaceDelimitedArray) UnmarshalText(text []byte) error {
	*s = strings.Split(string(text), " ")
	return nil
}

func (s SpaceDelimitedArray) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

func (s SpaceDelimitedArray) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *SpaceDelimitedArray) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	*s = strings.Split(str, " ")
	return nil
}

type AuthMethod string

const (
	AuthMethodBasic         AuthMethod = "client_secret_basic"
	AuthMethodPost          AuthMethod = "client_secret_post"
	AuthMethodNone          AuthMethod = "none"
	AuthMethodPrivateKeyJWT AuthMethod = "private_key_jwt"
)

var AllAuthMethods = []AuthMethod{
	AuthMethodBasic, AuthMethodPost, AuthMethodNone, AuthMethodPrivateKeyJWT,
}
