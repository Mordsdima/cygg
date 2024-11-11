module main

import encoding.hex
import encoding.base64
import crypto.blake3
import db.sqlite
import time
import arrays
import math
import crypto.ed25519
import x.json2

pub struct Block {
pub mut:
	ts           time.Time = time.utc()
	tooktomine   i64
	data         string
	sig          string
	prev         string
	nonce        int = -1
	diff         int
	generated_by string // waddr
	hash         string @[primary]
	version      int
}

pub fn (b Block) get_hash() string {
	return hex.encode(blake3.sum256('${b.get_dhash()};${b.nonce.str()};${b.sig}'.bytes()))
}

pub fn (b Block) get_dhash() string {
	return hex.encode(blake3.sum256('v${b.version.str()};${b.prev};${b.ts.unix().str()};${b.data};${b.diff.str()}'.bytes()))
}

pub fn (mut b Block) signit(using_key ed25519.PrivateKey) ! {
	b.sig = base64.encode(using_key.sign(b.get_dhash().bytes())!)
}

pub fn (mut b Block) mine(diff int) {
	s := time.now()
	b.nonce = 0
	b.diff = diff
	target := '0'.repeat(diff)
	for {
		if b.hash.starts_with(target) {
			break
		}
		b.nonce += 1
		b.hash = b.get_hash()
	}
	b.tooktomine = (time.now() - s).nanoseconds()
}

pub fn (b Block) validate(diff int, from Peer) ! {
	if b.get_hash() != b.hash && !b.hash.starts_with('0'.repeat(diff)) {
		return error('Something wrong with block.')
	}

	if ed25519.verify(from.pkey, b.get_dhash().bytes(), base64.decode(b.sig))! == false {
		return error('Invalid sign')
	}

	// validation ok? TODO: Validate all transaction so user couldnt to break blockchain
}

pub struct Blockchain {
pub mut:
	diff       int
	block_time int = 37
	chain      []Block
}

pub fn (mut bc Blockchain) db_register(mut db sqlite.DB, block Block) ! {
	sql db {
		insert block into Block
	}!
}

pub fn (mut bc Blockchain) load(mut db sqlite.DB) ! {
	chain := sql db {
		select from Block
	}!

	for i in chain {
		bc.chain << i
	}

	bc.diff = (bc.get_last() or { Block{} }).diff
}

pub fn (mut bc Blockchain) get_last() ?Block {
	if bc.chain.len == 0 {
		return none
	}
	return bc.chain.last()
}

pub fn (mut bc Blockchain) add_block(mut db sqlite.DB, mut block Block, register bool) ! {
	block.prev = (bc.get_last() or {
		Block{
			hash: '0'
		}
	}).hash
	block.hash = block.get_hash()
	if block.nonce == -1 {
		block.mine(bc.diff)
	}

	// TODO: Validation

	bc.chain << block

	if bc.chain.len != 0 && bc.chain.len % 482 == 0 {
		if (arrays.fold[Block, time.Duration](bc.chain[(bc.chain.len - diff_change_every_block)..bc.chain.len],
			0, fn (r time.Duration, t Block) int {
			return r + t.tooktomine
		}) / diff_change_every_block) < (bc.block_time * time.second) {
			bc.diff += 1
		} else if bc.diff > 1 {
			bc.diff -= 1
		}
	}

	if register {
		bc.db_register(mut db, block)!
	}
}

pub fn (mut bc Blockchain) create_genesis(mut db sqlite.DB) ! {
	bc.add_block(mut db, mut (Block{
		data:         'genesis'
		version:      -1
		sig:          'null'
		prev:         '0'
		diff:         1
		generated_by: base64.encode_str('genesis')
	}), true)!
}

pub fn (mut bc Blockchain) get_by_hash(hsh string) ?Block {
	for i in bc.chain {
		if i.hash == hsh {
			return i
		}
	}
	return none
}

pub fn (mut bc Blockchain) get_between(a string, b string) []Block {
	// Уфф
	ai := bc.chain.index(bc.get_by_hash(a) or { return [] })
	bi := bc.chain.index(bc.get_by_hash(b) or { return [] })

	return bc.chain[ai..bi + 1]
}

pub fn calculate_reward(prev Block, current Block, totally_blocks int) f64 {
	return math.round_sig((time.Duration(prev.tooktomine).seconds() / (totally_blocks - 1)) / (time.Duration(current.tooktomine).seconds() / (
		totally_blocks + 1)), 5)
}

pub fn (mut bc Blockchain) recalc_balances() !(f64, map[string]f64) {
	mut balances := map[string]f64{}
	mut turnover := f64(0)

	for i, block in bc.chain {
		// genesis is not counted
		if i == 0 {
			continue
		}

		prev := bc.chain[i - 1]
		rew := calculate_reward(prev, block, i)
		turnover += rew
		if json2.decode[map[string]string](block.data)!['type'] == 'coinbase' {
			coinbase := json2.decode[CoinbaseTransaction](block.data)!
			balances[coinbase.to] += rew
		}
	}

	return turnover, balances
}

pub const halving_every_block = 4860 // i486!!
pub const diff_change_every_block = 482
pub const can_be_mined = true
