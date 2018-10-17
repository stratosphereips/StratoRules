
//possible umbrella rule for cryptominers. regardless of intent, this kind of software
//is not allowed on Emerson environment. Focus of rule is on open source cryptominers

rule possible_cryptominer_minerd
{
	meta:
		author = "civilsphere, jowabels"
		date = "1/23/2018"
		description = "rule for executables based on minerd software (supports various coins)"
		reference = "https://github.com/pooler/cpuminer"

	strings:
		$crypto = "crypto" ascii nocase
		$cpuminer = "cpuminer" ascii nocase

		$minerd1 = "minerd --help" ascii nocase
		$minerd2 = "minerd [OPTIONS]" ascii nocase

		//author related information
		$author1 = "Miner by yvg1900" ascii nocase
		$author2 = "yvg1900@gmail.com" ascii nocase
		$author3 = "MINERGATE" ascii

		//some supported coins
		$coin1 = "MemoryCoin" ascii
		$coin2 = "MaxCoin" ascii
		$coin3 = "DiamondCoin" ascii
		$coin4 = "DvoraKoin" ascii
		$coin5 = "MyriadCoin" ascii
		$coin6 = "ByteCoin" ascii
		$coin7 = "QuazarCoin" ascii
		$coin8 = "FantomCoin" ascii
		$coin9 = "GroestlCoin" ascii
		$coin10 = "ProtoSharesCoin" ascii
		$coin11 = "MoneroCoin" ascii

		//sites to forward mined hashes
		$site1 = "pool.minexmr.com" ascii nocase
		$site2 = "monero.crypto-pool.fr" ascii nocase
		$site3 = "pool.cryptoescrow.eu" ascii nocase
		$site4 = "xmr.hashinvest" ascii nocase
		$site5 = "monero.farm" ascii nocase
		$site6 = "cryptonotepool.org.uk" ascii nocase
		$site7 = "monerominers.net" ascii nocase
		$site8 = "extremepool.org" ascii nocase
		$site9 = "mine.moneropool.org" ascii nocase
		$site10 = "mmcpool.com" ascii nocase
		$site11 = "dwarfpool.com" ascii nocase
		$site12 = "maxcoinpool.com" ascii nocase
		$site13 = "coinedpool.com" ascii nocase
		$site14 = "mining4all.eu" ascii nocase
		$site15 = "nut2pools.com" ascii nocase
		$site16 = "rocketpool.co.uk" ascii nocase
		$site17 = "miningpoolhub.com" ascii nocase
		$site18 = "nonce-pool.com" ascii nocase
		$site19 = "p2poolcoin.com" ascii nocase
		$site20 = "cryptity.com" ascii nocase
		$site21 = "extremepool.com" ascii nocase
		$site22 = "crypto-pool.fr" ascii nocase
		$site23 = "cryptoescrow.eu" ascii nocase
		$site24 = "moneropool.com" ascii nocase
		$site25 = "coinmine.pl" ascii nocase
		$site26 = "moneropool.com.br" ascii nocase
		$site27 = "moneropool.org" ascii nocase
		$site28 = "cryptohunger.com" ascii nocase


	condition:
		(ft_elf or ft_exe) and 
		((#crypto > 10 and #cpuminer > 3 and all of ($minerd*)) or 
		(#crypto > 3 and 1 of ($author*) and 1 of ($coin*) and 1 of ($site*)))

}


rule possible_cryptominer_xmrig
{
	meta:
		company = "Emerson"
		author = "civilsphere, jowabels"
		date = "1/23/2018"
		description = "rule for executables based on XMRig (monero miner)"
		reference = "https://github.com/xmrig/xmrig"

	strings:
		$c1 = "crypto" ascii nocase

		$x1 = "xmrig" ascii nocase

		$m1 = "xmrig [OPTIONS]" ascii nocase
		$m2 = "minergate.com" ascii nocase

	condition:
		(ft_elf or ft_exe) and #c1 > 4 and #x1 > 5 and any of ($m*)
}


rule possible_cryptominer_bfgminer
{
        meta:
                author = "civilsphere, jowabels"
                date = "1/26/2018"
                description = "rule to detect possible bfgminer based miners"
		reference = "https://github.com/luke-jr/bfgminer"

        strings:
                $bfg = "bfgminer" ascii nocase

                $cterra = "cointerra" ascii nocase

                //hardware stuff
                $h1 = "ASIC" ascii
                $h2 = "FPGA" ascii nocase
                $h3 = "GPU" ascii
                $h4 = "RPC" ascii

        condition:
                (ft_elf or ft_exe) and #bfg > 5 and #cterra > 5 and all of ($h*)

}


rule possible_cryptominer_ethminer
{
	meta:
		author = "civilsphere, jowabels"
		data = "1/26/2018"
		description = "rule to detect possible ethminer based miners"
		reference = "https://github.com/ethereum-mining/ethminer"

	strings:
		$eth = "ethminer" ascii nocase

		//c++ libraries
		$lib1 = "libethcore" ascii nocase
		$lib2 = "libdevcore" ascii nocase
		$lib3 = "libethash-cuda" ascii nocase

		//openCL, CUDA, stratum support
		$s1 = "opencl" ascii nocase
		$s2 = "cuda" ascii nocase
		$s3 = "stratum" ascii nocase

	condition:
		(ft_elf or ft_exe) and #eth > 5 and all of ($lib*) and all of ($s*)

}


rule possible_cryptominer_xmr_stak
{
	meta:
		author = "civilsphere, jowabels"
		data = "1/26/2018"
		description = "rule to detect possible xmr-stak based miners"
		reference = "https://github.com/fireice-uk/xmr-stak"

	strings:
		$stak = "xmr-stak" ascii nocase

		$c1 = "aeon" ascii nocase
		$c2 = "monero" ascii nocase
		$c3 = "stratum" ascii nocase

	condition:
		(ft_elf or ft_exe) and #stak > 10 and all of ($c*)

}


rule is_pe
{
	condition:
		uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550
}


rule is_elf
{
	strings:
		$elf = { 7f 45 4c 46 }
	condition:
		$elf in (0..4)
}

