module main

import toml
import os
import encoding.hex
import crypto.ed25519
import db.sqlite

fn peer() ! {
	mut conf_file := 'config.toml'

	if 'CONFIG' in os.environ() {
		conf_file = os.environ()['CONFIG']
	}

	cnf := toml.parse_file(conf_file) or { panic(err) }

	mut private := ed25519.PrivateKey{}
	if cnf.value('wallet.privateseed') == toml.null {
		println('No wallet found')
		// private = hex.encode(bcrypt.generate_salt().bytes())
		_, private = ed25519.generate_key()!
		mut f := os.open_append(conf_file) or { panic(err) }
		f.write_string("\n\n# THIS PART IS AUTOGENERATED\n[wallet]\nprivateseed=\"${hex.encode(private.seed())}\"") or {
			panic(err)
		}
		f.close()
		println('New generated wallet! Keep your config in ABSOLUTE secret!')
		panic('Restart application.')
	} else {
		private = ed25519.new_key_from_seed(hex.decode(cnf.value('wallet.privateseed').string())!)
		// unsafe { C.memcpy(&private[0], &cnf.value('wallet.private').array()[0], 32) }
	}

	mut db := sqlite.connect(cnf.value('peer.bc_path').string()) or { panic(err) }
	db.synchronization_mode(.off)!

	sql db {
		create table Block
	}!

	(*bc).load(mut db) or { panic(err) }

	mut mepeer := MePeer{
		skey: private
		port: u16(cnf.value('peer.port').int())
		db:   db
	}

	mepeer.init()

	for s in cnf.value('bootstrap.peers').array() {
		mepeer.add_peer(s.string())!
	}

	if cnf.value('bootstrap.peers').array().len == 0 && bc.chain.len == 0 {
		// new network?
		(*bc).diff = 1 // A simple difficulty! Right?
		(*bc).create_genesis(mut db) or { panic(err) }
	}

	mepeer.sync_peers() or { panic(err) }

	// check if our blockchain is uptodate
	if cnf.value('bootstrap.peers').array().len != 0 {
		// if we dont have any peers then likely we have newest?
		// anyway
		// Ask all nodes about genesis and last block
		if bc.chain.len != 0 {
			genesis := mepeer.request_genesis_block()!
			last := mepeer.request_last_block()!
			if genesis == bc.chain[0].hash
				&& last == ((*bc).get_last() or { panic('Блять') }).hash {
				println('Blockchain is up-to date!')
			}
		} else {
			genesis := mepeer.request_genesis_block()!
			last := mepeer.request_last_block()!
			mepeer.request_blocks(genesis, last)!
		}
	}

	println('Done! Running peer!')

	for {
		mepeer.update() or { panic(err) }
	}
}
