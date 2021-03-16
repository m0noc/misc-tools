#!/usr/bin/perl -w
#
# Usage:
# ntdsPwd.pl <NTDSfile> <lmFile> <ntlmFile> <pwdTopN>
#
# Will create:
# 	lm.passwords.out containing cracked passwords either native or in HEX (comment
# 		out the relevant bit; yes - should be a switch but meh.
# 	lm.hashes.remaining file
#
# Will output to stdout
# <user>:<rid>:<lmHash>:[crackedLM],<ntlmHash>,[crackedNTLM]
#
# Will output to stderr some stats on the data
#
# where:
# 	NTDSfile is the NTDS (text form) dump file
# 	lmFile is the hashcat "--show" output for the LM hashes
# 	ntlmFile is the hashcat "--show" output for the NTLM hashes
#
# Example:
# Do some LM cracking (wordlists, masks, etc)
# hashcat -O -m 3000 --potfile-path lm.pot --show lm.hash > cracked-lm.txt
# perl ntdsPwds.pl my.ntds cracked-lm.txt cracked-ntlm.txt 5 > my.out
# hashcat -O -m 1000 --potfile-path ntlm.pot -r lm2ntlm.rule ntlm.hash lm.passwords.out
# Do some more NTLM cracking (wordlists, masks, etc)
# hashcat -O -m 1000 --potfile-path ntlm.pot --show ntlm.hash > cracked-ntlm.txt
# perl ntdsPwds.pl my.ntds cracked-lm.txt cracked-ntlm.txt 5 > my.out
# Repeat and tweak
#
use strict;

my $ntdsFile = shift @ARGV;
my $lmFile = shift @ARGV;
my $ntlmFile = shift @ARGV;
my $pwdUsePrint = shift @ARGV;

my %users;
my %hashLM;
my %hashNTLM;

my %stats;
my %pwdUse;
my %pwdUseEnabledUsers;
my %pwdTot;
my %pwdTotEnabledUsers;
my %lmUncracked;

$hashLM{'aad3b435b51404eeaad3b435b51404ee'} = "";
$hashNTLM{'31d6cfe0d16ae931b73c59d7e0c089c0'} = "";

my $lmPwdOut = "lm.passwords.out";
my $lmRemain = "lm.hashes.remaining";

#
# hashcat will represent a *whole hash* as hex, so for LM this infers the combined thing
# may contain two if we read ithe pot file; BUT they will be at the start and end, not some
# random location in the middle. We can therefore implement a simple check for both without
# risking "conversion" of an actual password that is "$HEX[....]"
#
sub findHEX {
        my ($a) = @_;
	my $extra = "";

        if ($a =~ m/^\$HEX\[([^]]+)\](.*)$/) {
                my $match = $1;
                my @c = split //, $match;
                my $result = "";
		$extra = $2;
                foreach (my $i = 0; $i < length($match); $i+= 2 ) {
                        $result .= sprintf("%s", chr(hex($c[$i] . $c[$i+1] )));
                }
                $a =~ s/\$HEX\[$match\]/$result/;
        }
        if ($extra =~ m/^\$HEX\[([^]]+)\]$/) {
                my $match = $1;
                my @c = split //, $match;
                my $result = "";
                foreach (my $i = 0; $i < length($match); $i+= 2 ) {
                        $result .= sprintf("%s", chr(hex($c[$i] . $c[$i+1] )));
                }
		# The "extra" should still be in $a (at the end!)
                $a =~ s/\$HEX\[$match\]$/$result/;
        }
        return $a;
}

open(NTDS,$ntdsFile) || die("ntds");
while (<NTDS>) {
	chomp;
	my ($user,$rid,$lm,$ntlm,$rest) = split /:/,$_,5;
	$users{$user}{rid} = $rid;
	$users{$user}{lm} = $lm;
	#printf STDERR "debug: [%s]: ", $rest;
	if ($rest =~ m/\(status=Enabled\)/) {
		$users{$user}{enabled} = "yes";
		#printf STDERR "yes\n";
	} else {
		#printf STDERR "no\n";
	}
	#if (length($lm) != 32) {
	#	printf "ERROR: %s\n", $_;
	#	exit(1);
	#}
	if ($lm ne "") {
		$users{$user}{lm1} = substr($lm,0,16);
		$users{$user}{lm2} = substr($lm,16,16);
	} else {
		$users{$user}{lm1} = "";
		$users{$user}{lm2} = "";
	}
	$users{$user}{ntlm} = $ntlm;
}
close(NTDS);

# hashcat --show will show full length hash
open(LM,$lmFile) || die("lm");
while (<LM>) {
	chomp;
	s/\r$//;
	my ($hash,$pwd) = split /:/;
	my $realPwd;
	if ($pwd =~ m/\[notfound\]/) {
		my ($lm1,$lm2) = (substr($hash,0,16),substr($hash,16,16));
		if ($pwd =~ m/^\[notfound\](.*)$/) {
			my $pwd1 = $1;
			if ($pwd1 ne "") {
				$hashLM{$lm2} = findHEX($pwd1);
			}
		}
		if ($pwd =~ m/^(.*)\[notfound\]$/) {
			my $pwd1 = $1;
			if ($pwd1 ne "") {
				$hashLM{$lm1} = findHEX($pwd1);
			}
		}
	} else {
		$realPwd = findHEX($pwd);
		#$realPwd = findHEX($realPwd);
		#printf LMOUT "%s\r\n", $realPwd;
		$hashLM{$hash} = $realPwd;
	}
}
close(LM);

# NTLM
open(NTLM,$ntlmFile) || die("lm");
while (<NTLM>) {
	chomp;
	s/\r$//;
	my ($hash,$pwd) = split /:/;
	my $realPwd;
	$realPwd = findHEX($pwd);
	#$realPwd = findHEX($realPwd);
	#printf NTLMOUT "%s\r\n", $realPwd;
	# As *end* one in list any "," etc should be obvious
	#$hashNTLM{$hash} = "[" . $realPwd . "]";
	$hashNTLM{$hash} = $realPwd;
}
close(LM);

# Stat summary
$stats{total} = 0;
$stats{users}= 0;
$stats{usersCracked}= 0;
$stats{computers}= 0;
$stats{computersCracked}= 0;
$stats{history} = 0;
$stats{historyCracked} = 0;
$stats{enabledUsers}= 0;
$stats{enabledUsersCracked}= 0;
$stats{enabledComputers}= 0;
$stats{enabledComputersCracked}= 0;
$stats{enabledUsersCrackedLM}= 0;

foreach my $user (sort keys %users) {
	my $lm = defined($hashLM{$users{$user}{lm}}) ? $hashLM{$users{$user}{lm}} : "";
	my $ntlm = defined($hashNTLM{$users{$user}{ntlm}}) ? $hashNTLM{$users{$user}{ntlm}} : "";
	my $enabled = defined($users{$user}{enabled}) ? "yes" : "";
	my $lmCracked = 0;
	$stats{total} ++;

	if ($lm eq "") {
		my $both = 0;
		if (defined($hashLM{$users{$user}{lm1}})) {
			$lm .= $hashLM{$users{$user}{lm1}};
			$both++;
		} else {
			$lm .= "[notfound]";
			$lmUncracked{$users{$user}{lm1}} ++;
		}
		if (defined($hashLM{$users{$user}{lm2}})) {
			$lm .= $hashLM{$users{$user}{lm2}};
			$both++;
		} else {
			$lmUncracked{$users{$user}{lm2}} ++;
			$lm .= "[notfound]";
		}
		if ($both == 1) {
			printf STDERR "[W] Incomplete LM crack for %s\n", $user;
		} elsif ($both == 2) {
			# So we dump it for the LM - NTLM attack
			$hashLM{$users{$user}{lm}} = $lm;
			$lmCracked = 1;
		}
	} else {
		$lmCracked = 1;
	}

	# Any potential conflicts between hashes?
	if (($lmCracked == 1) && ($lm ne "") && ($ntlm ne "") && ($lm ne uc($ntlm))) {
		printf STDERR "[W] LM != uc NTLM for %s ([%s] != [%s])\n", $user, $lm, uc $ntlm;
		printf STDERR "[D]   LM %s\n", join " ", map { sprintf("%02x", ord $_); } split(//,$lm);
		printf STDERR "[D] NTLM %s (converted to upper case)\n", join " ", map { sprintf("%02x", ord $_); } split(//,uc $ntlm);
		printf STDERR "[D] NTLM %s\n", join " ", map { sprintf("%02x", ord $_); } split(//,$ntlm);
	}

	my $realUser = $user;
	$realUser =~ s/_history\d+$//;
	if ($user ne $realUser) {
		$stats{history} ++;
		if ($ntlm ne "") {
			$stats{historyCracked} ++;
		}
	} else {
		# ASSUMPTION is that computers end in a '$'
		if ($realUser =~ m/\$$/) {
			$stats{computers} ++;
			if ($enabled ne "") { $stats{enabledComputers} ++; }
			if ($ntlm ne "") {
				$pwdUse{$ntlm} ++;
				$stats{computersCracked} ++;
				if ($enabled ne "") { $stats{enabledComputersCracked} ++; }
			}
		} else {
			$stats{users} ++;
			if ($enabled ne "") {
				$stats{enabledUsers} ++;
				$stats{enabledUsersCrackedLM} ++ if ($lmCracked == 1);
				$pwdUseEnabledUsers{$ntlm} ++ if ($ntlm ne "");
			}
			if ($ntlm ne "") {
				$stats{usersCracked} ++;
				if ($enabled ne "") { $stats{enabledUsersCracked} ++; }
				$pwdUse{$ntlm} ++;
			}
		}
	}

	printf "%s,%d,%s,%s,%s,%s\n",
		$user,
		$users{$user}{rid},
		$users{$user}{lm},
		$lm,
		$users{$user}{ntlm},
		$ntlm
		;
}

open(LMOUT,">",$lmPwdOut) || die("lmOut");
foreach my $pwd (values %hashLM) {
	my @p = split //, $pwd;
	#printf LMOUT "%s\r\n", $pwd;
	printf LMOUT "\$HEX[";
	foreach my $c (@p) {
		printf LMOUT "%02x", ord($c);
	}
	printf LMOUT "]\r\n";
}
close(LMOUT);

open(LMREMAIN,">",$lmRemain) || die("lmRemain");
# lmUncracked
foreach my $hash (keys %lmUncracked) {
	# Is "0000000000000000" a valid hash?
	if (
		($hash ne "") &&
		($hash ne "0000000000000000")
	) {
		printf LMREMAIN "%s\n", $hash;
	}
}
close(LMREMAIN);

printf STDERR "[I] Total entries: %d\n", $stats{total};
printf STDERR "[I] Total of %d/%d (%0.2f%%) ENABLED users cracked based on NTLM hits (remaining: %d)\n",
	$stats{enabledUsersCracked}, $stats{enabledUsers}, (100*$stats{enabledUsersCracked}/$stats{enabledUsers}),
	$stats{enabledUsers} - $stats{enabledUsersCracked}
	;
printf STDERR "[I] Total of %d/%d (%0.2f%%) ENABLED users LM hashes cracked based (remaining: %d)\n",
	$stats{enabledUsersCrackedLM}, $stats{enabledUsers}, (100*$stats{enabledUsersCrackedLM}/$stats{enabledUsers}),
	$stats{enabledUsers} - $stats{enabledUsersCrackedLM}
	;
printf STDERR "[I] Total of %d/%d (%0.2f%%) ENABLED computers cracked\n",
	$stats{enabledComputersCracked}, $stats{enabledComputers}, (100*$stats{enabledComputersCracked}/$stats{enabledComputers})
	;
printf STDERR "[I] Total of %d/%d (%0.2f%%) users cracked\n",
	$stats{usersCracked}, $stats{users}, (100*$stats{usersCracked}/$stats{users})
	;
printf STDERR "[I] Total of %d/%d (%0.2f%%) computers cracked\n",
	$stats{computersCracked}, $stats{computers}, (100*$stats{computersCracked}/$stats{computers})
	;
printf STDERR "[I] Total of %d/%d (%0.2f%%) history cracked\n",
	$stats{historyCracked}, $stats{history}, (100*$stats{historyCracked}/$stats{history})
	;

foreach my $pwd (keys %pwdUse) {
	push(@{$pwdTot{$pwdUse{$pwd}}}, $pwd );
}
foreach my $pwd (keys %pwdUseEnabledUsers) {
	push(@{$pwdTotEnabledUsers{$pwdUseEnabledUsers{$pwd}}}, $pwd );
}

my $topCount = 1;
printf STDERR "[I] Top passwords for all accounts\n";
foreach my $tot (sort { $b <=> $a } keys %pwdTot) {
	foreach my $pwd (@{$pwdTot{$tot}}) {
		printf STDERR "	%4d: %s\n", $tot, $pwd;
		$topCount++;
		last if ($topCount > $pwdUsePrint);
	}
	last if ($topCount > $pwdUsePrint);
}

$topCount = 1;
printf STDERR "[I] Top passwords for %d ENABLED users (NTLM cracked)\n", $stats{enabledUsers};
foreach my $tot (sort { $b <=> $a } keys %pwdTotEnabledUsers) {
	foreach my $pwd (@{$pwdTotEnabledUsers{$tot}}) {
		printf STDERR "	%4d (%2.2f%%): %s\n", $tot, 100*$tot/$stats{enabledUsers}, $pwd;
		$topCount++;
		last if ($topCount > $pwdUsePrint);
	}
	last if ($topCount > $pwdUsePrint);
}
