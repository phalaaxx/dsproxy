/*
BSD 2-Clause License

# Copyright (c) 2025, Bozhin Zafirov

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice, this
    list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
package clap

import (
	"flag"
	"fmt"
	"os"
	"path"
	"strings"
)

/* argumentHelp stores command line arguments info */
type argumentHelp struct {
	HasValue  bool
	ArgLen    int
	ShortName rune
	LongName  string
	HelpText  string
	Required  bool
	Value     interface{}
}

/* String representation of the argument help */
func (a argumentHelp) String(isTerminal bool, maxLen int) (result string) {
	/* option creates a printable option representation */
	option := func(name string, short bool, isTerminal bool) string {
		if len(name) == 0 {
			return ""
		}
		shortOption := map[bool]string{
			true:  "-",
			false: "--",
		}
		if !isTerminal {
			return fmt.Sprintf("%s%s", shortOption[short], name)
		}
		return fmt.Sprintf("\033[01;38m%s%s\033[00m", shortOption[short], name)
	}

	optLen := func(maxLen int) (oLen int) {
		oLen = maxLen - a.ArgLen + 2
		if !a.HasValue {
			oLen += 3
		}
		return
	}
	/* build option string */
	var optionStr string
	if a.ShortName != 0 {
		if len(a.LongName) != 0 {
			optionStr = fmt.Sprintf(
				"  %s, %s",
				option(string(a.ShortName), true, isTerminal),
				option(a.LongName, false, isTerminal),
			)
		} else {
			optionStr = fmt.Sprintf(
				"  %s",
				option(string(a.ShortName), true, isTerminal),
			)
		}
	} else {
		if len(a.LongName) != 0 {
			optionStr = fmt.Sprintf(
				"      %s",
				option(a.LongName, false, isTerminal),
			)
		}
	}
	if a.HasValue {
		if len(a.LongName) != 0 {
			optionStr = fmt.Sprintf("%s <%s>", optionStr, strings.ToUpper(a.LongName))
		}
	}
	/* add padding */
	optionStr = fmt.Sprintf(
		"%s%s%s",
		optionStr,
		strings.Repeat(" ", optLen(maxLen)),
		a.HelpText,
	)
	fmt.Printf("%s\n", optionStr)
	return
}

/* global variables */
var (
	argHelp    []argumentHelp
	isTerminal bool
)

/* genericAddVar is a wrapper around flag functions to add command line arguments */
func genericAddVar[T any](data *T, name string, initial T, usage string) {
	switch any(*data).(type) {
	case int:
		flag.IntVar(any(data).(*int), name, any(initial).(int), usage)
	case int64:
		flag.Int64Var(any(data).(*int64), name, any(initial).(int64), usage)
	case float64:
		flag.Float64Var(any(data).(*float64), name, any(initial).(float64), usage)
	case string:
		flag.StringVar(any(data).(*string), name, any(initial).(string), usage)
	case uint:
		flag.UintVar(any(data).(*uint), name, any(initial).(uint), usage)
	case uint64:
		flag.Uint64Var(any(data).(*uint64), name, any(initial).(uint64), usage)
	case bool:
		flag.BoolVar(any(data).(*bool), name, any(initial).(bool), usage)
	}
}

/* genericVar defines a T flag in the argument result */
func genericVar[T any](result *T, short rune, long string, value T, usage string, required bool) {
	/* add generic options */
	if short != 0 {
		genericAddVar[T](result, string(short), value, usage)
	}
	if len(long) != 0 {
		genericAddVar[T](result, long, value, usage)
	}
	_, isBool := any(value).(bool)
	/* calculate options length multiplier */
	multiplier := 1
	if !isBool {
		multiplier = 2
	}
	/* update help data */
	argHelp = append(
		argHelp,
		argumentHelp{
			HasValue:  !isBool,
			ArgLen:    4 + multiplier*len(long),
			ShortName: short,
			LongName:  long,
			HelpText:  usage,
			Required:  required,
			Value:     value,
		},
	)
}

/* generic defines a T flag and returns a pointer to it */
func generic[T any](short rune, long string, value T, usage string, required bool) *T {
	result := new(T)
	genericVar[T](result, short, long, value, usage, required)
	return result
}

/* define global clap functions */
var (
	/* define functions assigning pointer to a flag */
	StringVar  = genericVar[string]
	IntVar     = genericVar[int]
	Int64Var   = genericVar[int64]
	Float64Var = genericVar[float64]
	UintVar    = genericVar[uint]
	Uint64Var  = genericVar[uint64]
	BoolVar    = genericVar[bool]
	/* define functions returning pointer to a flag */
	String  = generic[string]
	Int     = generic[int]
	Int64   = generic[int64]
	Float64 = generic[float64]
	Uint    = generic[uint]
	Uint64  = generic[uint64]
	Bool    = generic[bool]
)

/* Var is a special-case function / wrapper around flag.Var for custom data type flags */
func Var(value flag.Value, shortName rune, longName string, helpText string, required bool) {
	if shortName != 0 {
		flag.Var(value, string(shortName), helpText)
	}
	if len(longName) != 0 {
		flag.Var(value, longName, helpText)
	}
	argHelp = append(
		argHelp,
		argumentHelp{
			HasValue:  true,
			ArgLen:    4 + 2*len(longName),
			ShortName: shortName,
			LongName:  longName,
			HelpText:  helpText,
			Required:  required,
			Value:     value,
		},
	)
}

/* errorHelp renders error message when required arguments are missing */
func errorHelp(isTerminal bool) string {
	/* prepare error message header */
	fmtStr := "\033[01;31merror:\033[00m the following arguments are not provided:\n"
	if !isTerminal {
		fmtStr = "error: the following arguments are not provided:\n"
	}
	/* add arguments to error message */
	for _, arg := range argHelp {
		if arg.Required {
			argStr := "  \033[00;32m--%s <%s>\033[00m\n"
			if !isTerminal {
				argStr = "  --%s <%s>\n"
			}
			fmtStr = fmt.Sprintf(
				"%s%s",
				fmtStr,
				fmt.Sprintf(argStr, arg.LongName, strings.ToUpper(arg.LongName)),
			)
		}
	}
	/* add usage information */
	usageHelp := "\033[04m\033[01;38mUsage:\033[00m \033[01;38m%s\033[00m"
	if !isTerminal {
		usageHelp = "Usage: %s"
	}
	for _, arg := range argHelp {
		if !arg.Required {
			continue
		}
		argHelp := "\033[01;38m--%s\033[00m <%s>"
		if !isTerminal {
			argHelp = "--%s <%s>"
		}
		usageHelp = fmt.Sprintf(
			"%s %s",
			fmt.Sprintf(
				usageHelp,
				path.Base(os.Args[0]),
			),
			fmt.Sprintf(
				argHelp,
				arg.LongName,
				strings.ToUpper(arg.LongName),
			),
		)
	}
	fmtStr = fmt.Sprintf("%s\n%s\n", fmtStr, usageHelp)
	/* add help tip */
	helpTip := "For more information, try '\033[01;38m--help\033[00m'."
	if !isTerminal {
		helpTip = "For more information, try '--help'."
	}

	return fmt.Sprintf("%s\n%s\n", fmtStr, helpTip)
}

/* usageHeader prints flags usage header */
func usageHeader(isTerminal bool) string {
	var header string
	var fmtStr string
	header = "\033[04m\033[01;38mUsage:\033[00m \033[01;38m%s\033[00m [OPTIONS]"
	if !isTerminal {
		header = "Usage: %s [OPTIONS]"
	}
	for _, arg := range argHelp {
		if arg.Required {
			fmtStr = "%s \033[01;38m--%s\033[00m <%s>"
			if !isTerminal {
				fmtStr = "%s --%s <%s>"
			}
			header = fmt.Sprintf(
				fmtStr,
				header,
				arg.LongName,
				strings.ToUpper(arg.LongName),
			)
		}
	}
	optHdr := "\033[04m\033[01;38mOptions:\033[00m"
	if !isTerminal {
		optHdr = "Options:"
	}
	return fmt.Sprintf(
		"%s\n\n%s",
		fmt.Sprintf(header, path.Base(os.Args[0])),
		optHdr,
	)
}

/* ErrNoArg prints error and exits when no arguments are provided while at least one is required */
func ErrNoArg() {
	if isTerminal {
		fmt.Printf(
			"\033[01;31merror:\033[00m no arguments are provided\n\n" +
				"For more information, try '\033[01;38m--help\033[00m'.\n",
		)
	} else {
		fmt.Printf(
			"error: no arguments are provided\n\n" +
				"For more information, try '--help'.",
		)
	}
	os.Exit(-1)
}

/* Parse is a wrapper around flag.Parse function */
func Parse(required bool) {
	/* argCheck returns true if specified option is provided as a command line argument */
	argCheck := func(arg string) bool {
		for _, opt := range os.Args {
			if arg == opt {
				return true
			}
		}
		return false
	}
	/* print error on empty arguments list when at least one argument is required */
	if required && len(os.Args) == 1 {
		ErrNoArg()
	}
	/* parse and check if required arguments are provided */
	flag.Parse()
	for _, arg := range argHelp {
		/* do not check non-mandatory and bool arguments */
		if !arg.Required || !arg.HasValue {
			continue
		}
		/* make sure value is provided */
		if !argCheck("--"+arg.LongName) && (arg.ShortName == 0 || !argCheck("-"+string(arg.ShortName))) {
			fmt.Printf(errorHelp(isTerminal))
			os.Exit(-1)
		}
	}
}

/* initialize clap parser */
func init() {
	/* determine if program is running inside a terminal */
	if fileInfo, _ := os.Stdout.Stat(); (fileInfo.Mode() & os.ModeCharDevice) != 0 {
		isTerminal = true
	}
	/* replace flag usage */
	flag.Usage = func() {
		maxLength := int(0)
		/* get the length of the longest argument */
		for idx := range argHelp {
			if argHelp[idx].ArgLen > maxLength {
				maxLength = argHelp[idx].ArgLen
			}
		}
		/* print header */
		fmt.Printf("%s\n", usageHeader(isTerminal))
		/* print options */
		for _, arg := range argHelp {
			fmt.Printf(arg.String(isTerminal, maxLength))
		}
	}
}
