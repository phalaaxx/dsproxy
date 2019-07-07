package main

import (
	"net/http"
	"text/template"
)

/* Global Constants */
const (
	TemplateData404 = `<html>
<head>
</head>
<body>
<h2>404 Not Found</h2>
<h3>Requested resource {{.}} was not found</h3>
<hr>
<i>Generated by Dead Simple Proxy</i>
<body>
</html>`
)

/* Global Variables */
var (
	Template404 *template.Template
)

/* Initialize global templates */
func init() {
	Template404 = template.Must(
		template.New("404").Parse(TemplateData404),
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
