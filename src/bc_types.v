module main

pub struct CoinbaseTransaction {
pub mut:
	@type string @[json: 'type']
	to    string // addr
	rig   string // Rig
}

pub struct SingleTransaction {
pub mut:
	from    string
	to      string
	comment string
}

pub struct Transactions {
pub mut:
	@type string @[json: 'type']
	trans []SingleTransaction
}
