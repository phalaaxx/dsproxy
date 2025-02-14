package main

import (
	_ "embed"
	"net/http"
	"text/template"
)

/* Global Constants */
var (
	//go:embed static/404.html
	TemplateData404 string

	//go:embed static/stats.html
	TemplateDataStats string

	//go:embed static/edit.html
	TemplateDataEdit string

	//go:embed static/new.html
	TemplateDataNew string
)

/* Global Variables */
var (
	Template404   *template.Template
	TemplateStats *template.Template
	TemplateEdit  *template.Template
	TemplateNew   *template.Template
)

/* Initialize global templates */
func init() {
	Template404 = template.Must(
		template.New("404").Parse(TemplateData404),
	)
	TemplateStats = template.Must(
		template.New("stats").Parse(TemplateDataStats),
	)
	TemplateEdit = template.Must(
		template.New("edit").Parse(TemplateDataEdit),
	)
	TemplateNew = template.Must(
		template.New("new").Parse(TemplateDataNew),
	)
}

/* Render404 generates a 404 Not Found page */
func Render404(w http.ResponseWriter, what string) error {
	w.WriteHeader(http.StatusNotFound)
	if err := Template404.Execute(w, what); err != nil {
		return err
	}
	return nil
}

/* RenderStats generates a statistics page */
func RenderStats(w http.ResponseWriter, data interface{}) error {
	return TemplateStats.Execute(w, data)
}

/* RenderEdit generates endpiont edit form */
func RenderEdit(w http.ResponseWriter, endpoint EndPointBackend) error {
	return TemplateEdit.Execute(w, endpoint)
}

/* RenderNew generates a new endpoint form view */
func RenderNew(w http.ResponseWriter) error {
	return TemplateNew.Execute(w, nil)
}
