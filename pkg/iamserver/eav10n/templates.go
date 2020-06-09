package eav10n

import (
	htmltpl "html/template"
	"path/filepath"
	texttpl "text/template"

	"golang.org/x/text/language"
)

var (
	localizedAccountActivationBodyHTMLTemplates map[string]*htmltpl.Template

	//TODO: load these from somewhere (static storage)
	localizedAccountActivationBodyHTMLTemplateSources = map[string][]string{
		"account-activation-en.html": {"en", "en-US", "en-GB"},
		"account-activation-id.html": {"id", "id-ID"},
	}

	localizedAccountActivationSubjectTemplates map[string]*texttpl.Template

	//TODO: load these from somewhere (static storage)
	localizedAccountActivationSubjectTemplateSources = map[string][]string{
		"{{ .AppName }} - Account Activation": {"en", "en-US", "en-GB"},
		"{{ .AppName }} - Aktifasi Akun":      {"id", "id-ID"},
	}
)

func loadTemplates(resourcesDir string) {
	loadSubjectTemplates()
	loadBodyTemplates(resourcesDir)
}

func loadSubjectTemplates() {
	localizedAccountActivationSubjectTemplates = make(map[string]*texttpl.Template)
	for tplstr, locales := range localizedAccountActivationSubjectTemplateSources {
		if len(locales) == 0 {
			continue
		}
		tpl := texttpl.Must(texttpl.New("subject").Parse(tplstr))
		for _, locale := range locales {
			if locale == "" {
				continue
			}
			langTag := language.MustParse(locale)
			if _, ok := localizedAccountActivationSubjectTemplates[langTag.String()]; ok {
				panic("duplicate for locale " + locale + " (" + langTag.String() + ")")
			}
			localizedAccountActivationSubjectTemplates[langTag.String()] = tpl
		}
	}
	// Ensure that we have a message template for the default locale.
	if v := localizedAccountActivationSubjectTemplates[messageLocaleDefault.String()]; v == nil {
		panic("no template for default locale " + messageLocaleDefault.String())
	}
}

func loadBodyTemplates(resourcesDir string) {
	localizedAccountActivationBodyHTMLTemplates = make(map[string]*htmltpl.Template)
	// Load all message templates. We also ensure that there's no
	// duplicates for the same language.
	for tplfname, locales := range localizedAccountActivationBodyHTMLTemplateSources {
		if len(locales) == 0 {
			continue
		}

		fname := filepath.Join(resourcesDir, "emails", tplfname)
		tpl := htmltpl.Must(htmltpl.ParseFiles(fname))
		for _, locale := range locales {
			if locale == "" {
				continue
			}
			langTag := language.MustParse(locale)
			if _, ok := localizedAccountActivationBodyHTMLTemplates[langTag.String()]; ok {
				panic("duplicate for locale " + locale + " (" + langTag.String() + ")")
			}
			localizedAccountActivationBodyHTMLTemplates[langTag.String()] = tpl
		}
	}
	// Ensure that we have a message template for the default locale.
	if v := localizedAccountActivationBodyHTMLTemplates[messageLocaleDefault.String()]; v == nil {
		panic("no template for default locale " + messageLocaleDefault.String())
	}
}
