package main

import (
	"fmt"
	"os"

	"github.com/idzoid/cryptozoid/internal/cli"
	"github.com/jessevdk/go-flags"
)

// Root options
type Options struct {
	Verbose bool `short:"v" long:"verbose" description:"Enable verbose mode"`
}

// Subcommand: info
type InfoCommand struct {
	Detail bool `short:"d" long:"detail" description:"Show detailed info"`
}

func (cmd *InfoCommand) Execute(args []string) error {
	if cmd.Detail {
		fmt.Println("Showing detailed info.")
	} else {
		fmt.Println("Showing basic info.")
	}
	return nil
}

func main() {
	var opts Options

	parser := flags.NewParser(&opts, flags.Default)
	parser.AddCommand("ecdh", "Generate ECDH key", "Generate an Eliptic Curve Diffie-Hellman key key", &cli.EcdhCommand{})
	parser.AddCommand("info", "Show info", "Show application info", &InfoCommand{})

	_, err := parser.Parse()
	if err != nil {
		// If no command is specified, show a friendly message and help
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrUnknownCommand {
			// fmt.Fprintf(os.Stderr, "%v\n", err)
			// fmt.Fprintln(os.Stderr, "Please specify one command of: ecgen or info")
			parser.WriteHelp(os.Stderr)
			os.Exit(1)
		}
		// For any other error, print the error and help
		// fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		parser.WriteHelp(os.Stderr)
		os.Exit(1)
	}
}
