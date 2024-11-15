module main

import cli
import os

fn main() {
	println('Hello World!')

	mut app := cli.Command{
		name:        'cygg'
		description: 'cygg'
		execute:     fn (cmd cli.Command) ! {
			println('no valid command provided! valid commands are: \npeer\nvalidator\nminer')
			return
		}
		commands:    [
			cli.Command{
				name:    'peer'
				execute: fn (cmd cli.Command) ! {
					peer() or { panic(err) }
				}
			},
			cli.Command{
				name:    'validator'
				execute: fn (cmd cli.Command) ! {
					validator() or { panic(err) }
				}
			},
			cli.Command{
				name:    'miner'
				execute: fn (cmd cli.Command) ! {
					miner() or { panic(err) }
				}
			},
		]
	}
	app.setup()
	app.parse(os.args)
}
