package main

import (
	"net/http"
	"text/template"
)

/* Global Constants */
const (
	TemplateData404 = `<!DOCTYPE html>
<html>
	<head>
		<title>Page Not Found - {{.}}</title>
	</head>
	<body>
		<h2>404 Not Found</h2>
		<h3>Requested resource {{.}} was not found</h3>
		<hr>
		<i>Generated by Dead Simple Proxy</i>
	<body>
</html>`

	TemplateDataStats = `<!DOCTYPE html>
<html>
	<head>
		<title>Proxy Statistics</title>
		<style>
			.heading {
				text-decoration: underline;
			};
			table {
				border-collapse: collapse;
				width: 100%;
			}
			th, td {
				text-align: left;
				padding: 0 20px 0 20px;
			}
			tr:nth-child(even) {
				background-color: #f2f2f2;
			}
			thead {
				font-weight: bold;
				background-color: #ccc;
			}
		</style>
	</head>
	<body>
		<h2 class=heading>Dead Simple Proxy, Statistics Page</h2>
		<h3>Global Statistics</h3>
		<table>
			<thead>
				<tr>
					<td>Parameter</td>
					<td>Value</td>
				</tr>
			</thead>
			<tbody>
				<tr>
					<td>Active Requests</td>
					<td>{{.ActiveRequests}}</td>
				</tr>
				<tr>
					<td>Requests per Second</td>
					<td>{{.RequestsPerSecond}}</td>
				</tr>
				<tr>
					<td>Total Requests</td>
					<td>{{.TotalRequests}}</td>
				</tr>
				<tr>
					<td>Server Uptime</td>
					<td>{{.ServerUptime}}</td>
				</tr>
			</tbody>
		</table>
		<h3>Configured Endpoints</h3>
		<table>
			<thead>
				<tr>
					<td>&#35;</td>
					<td>Local Path</td>
					<td>Upstream Address</td>
					<td>Options</td>
				</tr>
			</thead>
			<tbody>
			{{range $i, $EndPoint := .Backend}}
				<tr>
					<td>{{$i}}</td>
					<td>{{$EndPoint.LocalPath}}</td>
					<td>{{$EndPoint.Upstream}}</td>
					<td>
						<a
							href="/_control/edit?name={{$EndPoint.LocalPath}}"
							title="Change endpoint data {{$EndPoint.LocalPath}}">
							<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAALEwAACxMBAJqcGAAAAGpJREFUOI3FkUsOgCAMBQe9GDezR8OT6cJqDFqgdeFLuuAz0xTAF9EKRYBN65JMQdlySmYHVIAEZF1nIPUEoheLIVl78GPm21m9Z8KWxAWbkvoXhOOFQ2l17o7wH8xXuCUYgi3BMPwmcME7KuNKVCZRuEcAAAAASUVORK5CYII=">
						</a>
						<a
							href="/_control/remove?name={{$EndPoint.LocalPath}}"
							title="Remove endpoint {{$EndPoint.LocalPath}}"
							onClick="return confirm(
								'WARNING: Are you sure you want to remove endpoint {{$EndPoint.LocalPath}}?'
							);">
							<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAALEwAACxMBAJqcGAAAAOFJREFUOI2Vkk0OgjAQhT/YiBdBN4Z4BC+jB1IDC89ijIfAwB64Am6Ki07NpLaok7yknbw3//BpW6ACWuApaIASKAL8ty2BCzDNwEjwLCS+fxFr3PwgOnMn8EUd0Kt/qXvWpFzQBfwrYFDtFClwCMyjBXaSsZd3CySKkwB7R/ZLzYWUq/daZXd4gF1TqF8njIknYEwD5f9tzUz2tSBWRQ12HTHxIIgFOYI9T6MCrAJEF0T7DbBxbVQeOTQw33/Sc8iw5/nrKV+BhT/MTCoxM0IjmT/E2grgjD2SUVDLwDY++QUdKpC+p87z5AAAAABJRU5ErkJggg==">
						</a>
					</td>
				</tr>
			{{end}}
			</tbody>
		</table>
	</body>
</html>
`
	TemplateDataEdit = `<!DOCTYPE html>
<html>
	<head>
		<title>Proxy Statistics</title>
		<style>
			.heading {
				text-decoration: underline;
			};
			table {
				border-collapse: collapse;
				width: 100%;
			}
			th, td {
				text-align: left;
				padding: 0 20px 0 20px;
			}
			tr:nth-child(even) {
				background-color: #f2f2f2;
			}
			thead {
				font-weight: bold;
				background-color: #ccc;
			}
		</style>
	</head>
	<body>
		<h2 class=heading>Dead Simple Proxy</h2>
		<h3>Edit endpoint {{.LocalPath}}</h3>
		<form method="POST">
			<input type="text" name="address" value="{{.Upstream}}">
			<input type="submit" name="submit" value="Submit">
		</form>
	</body>
</html>`
)

/* Global Variables */
var (
	Template404   *template.Template
	TemplateStats *template.Template
	TemplateEdit  *template.Template
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
