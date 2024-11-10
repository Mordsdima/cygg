module main

// import hash.fnv1a
import crypto.blake3
import net
import crypto.ed25519
import encoding.base64
import time
import encoding.binary
import x.json2
import compress.zstd
import db.sqlite

pub enum PeerType {
	miner // lowest level
	peer
	validator // highest level
}

pub struct LazyPacket {
pub:
	from net.Addr
	data []u8
}

pub struct Peer {
mut:
	paddr net.Addr
	waddr string
	pkey  ed25519.PublicKey
	@type PeerType
}

pub struct MePeer {
mut:
	lzps []LazyPacket
pub:
	port u16
pub mut:
	// dht   map[u64][]string
	peers []Peer
	skey  ed25519.PrivateKey
	conn  net.UdpConn
	db    sqlite.DB
	apprs map[string]int
	denys map[string]int
	@type PeerType = .peer
}

fn (mp MePeer) sign_packet(p []u8) ![]u8 {
	mut sig := mp.skey.sign(p)!
	sig << p
	return sig
}

fn (mut mp MePeer) send_packet(to Peer, @type u8, d []u8) ! {
	mut tr := []u8{}
	tr << []u8{len: 8}
	binary.little_endian_put_u64_end(mut tr, u64(time.now().as_utc().unix_milli()))
	tr << @type
	tr << d
	mp.conn.write_to(to.paddr, mp.sign_packet(tr)!)!
}

fn (mut mp MePeer) request_active_peers(who_to_ask Peer) ! {
	mp.send_packet(who_to_ask, 0x02, [])!
}

fn (mut mp MePeer) check_pckt(sender Peer, p []u8) ! {
	// i guess we should check

	if ed25519.verify(sender.pkey, p[64..], p[..64])! == false {
		return error('Aw.. Not valid!')
	}
}

pub fn (mut mp MePeer) add_new_block(mut block Block, add bool) ! {
	// Thats a biggg process so..

	// First of all lets validate the block.
	if !block.validate() {
		println('invalid')
		return
	}

	// Also, if we alone we should just add this block to blockchain
	if (mp.peers.len == 0 && add) || (mp.peers.filter(it.@type == .validator).len == 0 && add) {
		(*bc).add_block(mut mp.db, mut block, true)!
		return
	}

	// Second of all lets send to all peers a new block
	for i in mp.peers.filter(it.@type == .validator) {
		mp.send_packet(i, 0x0b, zstd.compress(json2.encode(block).bytes())!)!
	}

	// Lets receive all confirmations and deniations
	totally_should_receive := mp.peers.filter(it.@type == .validator).len
	mut good := 0
	mut bad := 0

	if totally_should_receive == 0 {
		println('Cant process yet.')
		return
	}

	// СОБИРАЕМ ЛУКАСЫЫЫ

	mut p_buf := []u8{len: 64 + 8 + 1 + 1536} // 64 of sig, 8 of u64 of UTC timestamp in ms, 1 of packet type and 1536 of useful data
	mut i_len := 0
	for {
		if (good + bad) == totally_should_receive {
			break
		}
		mut from := net.Addr{}
		i_len, from = mp.conn.read(mut p_buf) or { panic(err) }
		if p_buf[72] == u8(0x0c) {
			good += 1
		} else if p_buf[72] == u8(0x0d) {
			bad += 1
		} else {
			mp.lzps << LazyPacket{
				from: from
				data: p_buf[0..i_len].clone()
			}
		}
	}
	if ((good / totally_should_receive) * 100) >= 95 {
		println('New valid block.')
		for i in mp.peers {
			println('sending...')
			mp.send_packet(i, 0x0e, zstd.compress(json2.encode(block).bytes())!)!
		}
		if add {
			(*bc).add_block(mut mp.db, mut block, true)!
		}
	} else {
		println('Uh-oh! Invalid block!')
	}
}

pub fn (mut mp MePeer) request_last_block() !string {
	mut blocks := {
		'0': 0
	}
	for i in mp.peers {
		mp.send_packet(i, 0x06, [])! // 0x07 will be answer
		mut p_buf := []u8{len: 64 + 8 + 1 + 1536} // 64 of sig, 8 of u64 of UTC timestamp in ms, 1 of packet type and 1536 of useful data
		mut i_len := 0
		for {
			mut from := net.Addr{}
			i_len, from = mp.conn.read(mut p_buf) or { panic(err) }
			if from == i.paddr {
				break
			} else {
				mp.lzps << LazyPacket{
					from: from
					data: p_buf[0..i_len].clone()
				}
			}
		}
		p_buf = p_buf[0..i_len].clone()

		mp.check_pckt(i, p_buf.clone())!

		// Lets think about it!

		p_buf.delete_many(0, 72)
		assert p_buf[0] == 0x07

		mut hash := p_buf.clone()
		hash.delete(0) // So its should be ok now
		shash := unsafe { tos(&hash[0], hash.len) }

		if shash in blocks {
			blocks[shash] += 1
		} else {
			blocks[shash] = 1
		}
	}

	mut max_key := ''
	mut max_value := -1

	for key, value in blocks {
		if value > max_value {
			max_value = value
			max_key = key
		}
	}

	return max_key
}

pub fn (mut mp MePeer) request_genesis_block() !string {
	mut blocks := {
		'0': 0
	}
	for i in mp.peers {
		mp.send_packet(i, 0x04, [])! // 0x05 will be answer
		mut p_buf := []u8{len: 64 + 8 + 1 + 1536} // 64 of sig, 8 of u64 of UTC timestamp in ms, 1 of packet type and 1536 of useful data
		mut i_len := 0
		for {
			mut from := net.Addr{}
			i_len, from = mp.conn.read(mut p_buf) or { panic(err) }
			if from == i.paddr {
				break
			} else {
				mp.lzps << LazyPacket{
					from: from
					data: p_buf[0..i_len].clone()
				}
			}
		}
		p_buf = p_buf[0..i_len].clone()

		mp.check_pckt(i, p_buf.clone())!

		// Lets think about it!

		p_buf.delete_many(0, 72)
		assert p_buf[0] == 0x05

		mut hash := p_buf.clone()
		hash.delete(0) // So its should be ok now
		shash := unsafe { tos(&hash[0], hash.len) }

		if shash in blocks {
			blocks[shash] += 1
		} else {
			blocks[shash] = 1
		}
	}

	mut max_key := ''
	mut max_value := -1

	for key, value in blocks {
		if value > max_value {
			max_value = value
			max_key = key
		}
	}

	return max_key
}

pub fn (mut mp MePeer) request_difficulty() !int {
	mut blocks := {
		0: 0
	}
	for i in mp.peers {
		mp.send_packet(i, 0x0f, [])! // 0x10 will be answer
		mut p_buf := []u8{len: 64 + 8 + 1 + 1536} // 64 of sig, 8 of u64 of UTC timestamp in ms, 1 of packet type and 1536 of useful data
		mut i_len := 0
		for {
			mut from := net.Addr{}
			i_len, from = mp.conn.read(mut p_buf) or { panic(err) }
			if from == i.paddr {
				break
			} else {
				mp.lzps << LazyPacket{
					from: from
					data: p_buf[0..i_len].clone()
				}
			}
		}
		p_buf = p_buf[0..i_len].clone()

		mp.check_pckt(i, p_buf.clone())!

		// Lets think about it!

		p_buf.delete_many(0, 72)
		assert p_buf[0] == 0x10

		mut d := p_buf.clone()
		d.delete(0) // So its should be ok now
		diff := int(binary.little_endian_u64(d))
		// shash := unsafe { tos(&hash[0], hash.len) }

		if diff in blocks {
			blocks[diff] += 1
		} else {
			blocks[diff] = 1
		}
	}

	mut max_key := 0
	mut max_value := -1

	for key, value in blocks {
		if value > max_value {
			max_value = value
			max_key = key
		}
	}

	return max_key
}

pub fn (mut mp MePeer) request_blocks(from string, to string) ! {
	mp.send_packet(mp.peers[0], 0x09, ('${from};${to}').bytes())!
}

pub fn (mut mp MePeer) init() {
	mp.conn = *(net.listen_udp('[::]:${mp.port}') or { panic(err) })
	mp.conn.set_read_timeout(time.second * 5)
}

fn (mut mp MePeer) connect_to_peer(mut peer Peer) ! {
	mut p_buf := []u8{cap: 64 + 8 + 1 + 1536} // 64 of sig, 8 of u64 of UTC timestamp in ms, 1 of packet type and 1536 of useful data
	p_buf << []u8{len: 64} // Empty signature because we dont know public key of peer
	p_buf << []u8{len: 8}
	binary.little_endian_put_u64_end(mut p_buf, u64(time.now().as_utc().unix_milli()))
	p_buf << u8(0x00) // Handshake = 0x00
	p_buf << u8(mp.@type) - 1
	p_buf << mp.skey.public_key()

	mp.conn.write_to(peer.paddr, p_buf)!
	mut i_len := 0

	for {
		mut from := net.Addr{}
		i_len, from = mp.conn.read(mut p_buf)!
		if from.str() == peer.paddr.str() {
			break
		} else {
			mp.lzps << LazyPacket{
				from: from
				data: p_buf.clone()
			}
		}
	}

	p_buf.delete_many(0, 72) // Signature at that moment is null anyway, starting from next message it will contain the signature! + ts not required

	assert p_buf[0] == 0x01 // Handshake Answer = 0x01

	// Our key is 32 bytes in len
	mut key := p_buf.clone()
	typeofpeer := unsafe { PeerType(key[1]) }
	key.delete_many(0, 2) // So its should be ok now

	assert key.len == 32

	peer.pkey = ed25519.PublicKey(key)

	peer.waddr = base64.encode(blake3.sum256(key))
	peer.@type = typeofpeer

	// Конор закончил проверку и выдал оценку 10/10!
}

pub fn (mut mp MePeer) add_peer(paddr string) ! {
	// paddr = Physical Addr (addr to connect via yggdrasil)
	// waddr = Wallet Addr (addr of wallet)

	// hash := fnv1a.sum64_string(waddr)
	mut peer := Peer{
		waddr: ''
		paddr: (net.resolve_addrs_fuzzy(paddr, .udp)!)[0]
	}

	// Lets try check the peer!
	mp.connect_to_peer(mut peer)!

	println('${peer.waddr} -> ${peer.paddr.str()}')

	mp.peers << peer
	// Lets try set in DHT
	// mp.put_dht(peer.waddr, paddr)
}

fn (mp MePeer) get_peer(addr net.Addr) ?Peer {
	for i in mp.peers {
		if i.paddr.str() == addr.str() {
			return i
		}
	}
	return none
}

fn (mut mp MePeer) process_packet(from net.Addr, data []u8) ! {
	println(data.len)
	pid := data[72]
	mut p_buf := data.clone()
	if pid == 0x00 { // Handshake so we dont need to check sig
		// Let save it!
		p_buf.delete_many(0, 72) // Signature at that moment is null anyway, starting from next message it will contain the signature! and also we dont timestamp then

		assert p_buf[0] == 0x00 // Handshake = 0x00
		typeofpeer := unsafe { PeerType(p_buf[1]) }

		// Our key is 32 bytes in len
		mut key := p_buf.clone()
		key.delete_many(0, 2) // So its should be ok now
		assert key.len == 32

		mut peer := Peer{}

		peer.@type = typeofpeer
		peer.paddr = from
		peer.pkey = ed25519.PublicKey(key)

		peer.waddr = base64.encode(blake3.sum256(key))

		mp.peers << peer

		mut s_buf := []u8{cap: 64 + 8 + 1 + 1536} // 64 of sig, 1 of packet type and 512 of useful data
		s_buf << []u8{len: 64} // Empty signature because we dont know public key of peer
		s_buf << []u8{len: 8}
		binary.little_endian_put_u64_end(mut s_buf, u64(time.now().as_utc().unix_milli()))
		s_buf << u8(0x01) // Handshake = 0x00
		s_buf << u8(mp.@type)
		s_buf << mp.skey.public_key()
		// unsafe { C.memcpy(&s_buf[p_buf.len - 32], &pkey[0], pkey.len) }

		mp.conn.write_to(from, s_buf)!
	} else if pid == 0x09 {
		p_buf.delete_many(0, 64 + 8 + 1)
		s := (unsafe { tos(&p_buf[0], p_buf.len) }).split(';')
		for i in (*bc).get_between(s[0], s[1]) {
			mp.send_packet(mp.get_peer(from) or { return error('Failed to handle block request!') },
				0x0a, zstd.compress(json2.encode(i).bytes())!)!
		}
	} else if pid == 0x04 {
		mp.send_packet(mp.get_peer(from) or {
			return error('Failed to handle genesis block request!')
		}, 0x05, (*bc).chain[0].hash.bytes())!
	} else if pid == 0x06 {
		mp.send_packet(mp.get_peer(from) or { return error('Failed to handle last block request!') },
			0x07, ((*bc).get_last() or { return }).hash.bytes())!
	} else if pid == 0x0a {
		p_buf.delete_many(0, 64 + 8 + 1)
		d_buf := zstd.decompress(p_buf)!
		mut b := json2.decode[Block](unsafe { tos(&d_buf[0], d_buf.len) })!
		(*bc).add_block(mut mp.db, mut b, true)!
	} else if pid == 0x0b {
		p_buf.delete_many(0, 64 + 8 + 1)
		d_buf := zstd.decompress(p_buf)!
		st := unsafe { tos(&d_buf[0], d_buf.len) }
		b := json2.decode[Block](st)!
		// So.. Lets validate block
		if b.validate() {
			mp.apprs[b.hash] = 1
			mp.denys[b.hash] = 0

			for i in mp.peers {
				if i.@type == .validator || i.paddr.str() == from.str() {
					mp.send_packet(i, 0x0c, b.hash.bytes())!
				}
			}
		}
	} else if pid == 0x0c {
		p_buf.delete_many(0, 64 + 8 + 1)
		b := unsafe { tos(&p_buf[0], p_buf.len) }
		if b in mp.apprs {
			mp.apprs[b] += 1
		} else {
			mp.apprs[b] = 1
		}
	} else if pid == 0x0d {
		p_buf.delete_many(0, 64 + 8 + 1)
		b := unsafe { tos(&p_buf[0], p_buf.len) }
		if b in mp.apprs {
			mp.denys[b] += 1
		} else {
			mp.denys[b] = 1
		}
	} else if pid == 0x0e {
		p_buf.delete_many(0, 64 + 8 + 1)
		d_buf := zstd.decompress(p_buf)!
		mut b := json2.decode[Block](unsafe { tos(&d_buf[0], d_buf.len) })!

		if b.hash in mp.apprs
			&& (mp.apprs[b.hash] / (mp.peers.filter(it.@type == .validator).len + 1) * 100) >= 95 {
			// println('Valid block yay!!!!!!!!!!!!!!!')
			(*bc).add_block(mut mp.db, mut b, true)!
		} else {
			panic('Back into the future.')
		}
	} else if pid == 0x0f {
		mp.send_packet(mp.get_peer(from) or { return error('Failed to handle request diff!') },
			0x10, binary.little_endian_get_u64(u64((*bc).diff)))!
	} else if pid == 0xfe {
		// Ping!
		mp.send_packet(mp.get_peer(from) or { return error('Failed to handle ping!') },
			0xff, [])!
		// Pong!
	} else if pid == 0xff {
		println('Pong!')
	} else {
		panic('No valid packet inputted')
	}
}

pub fn (mut mp MePeer) update() ! {
	// Update function
	if mp.lzps.len != 0 {
		p := mp.lzps.pop()
		mp.process_packet(p.from, p.data)!
	}

	mut p_buf := []u8{len: 64 + 8 + 1 + 1536} // 64 of sig, 1 of packet type and 1536 of useful data

	howmany, ip := mp.conn.read(mut p_buf) or { panic(err) }

	if howmany > 0 {
		mp.process_packet(ip, p_buf[0..howmany].clone())!
	}
}

pub fn (mut mp MePeer) sync_peers() ! {
	if mp.peers.len == 0 {
		return
	}
	// Syncs ALL peers (basically connects to all peers)
	mp.request_active_peers(mp.peers[0])! // and thats all!
}
