#!/usr/bin/perl -w
#
# Usage: run it to output the file (about 250KB) and then use it thus:
#
# perl ./hashcatLM2NTLMrules.pl > lm2ntlm.rule
# hashcat -O -m 1000 -r ./lm2ntlm.rule YOUR-NTLM-HASH-FILE YOUR-LM-CRACKED-PASSWORDS
#

use strict;

# Set to 14 for all LM -> NTLM
my $places = 14;
my $max = 2 ** $places;

my @offset = qw( 0 1 2 3 4 5 6 7 8 9 A B C D E F G H I J K L M N O P Q R S T U V W X Y Z );

#printf "Max: %d\n", $max;

for (my $i = 0 ; $i < $max; $i++ ) {
	my $o = "";
	for (my $j = 0 ; $j < $places; $j++ ) {
		my $mask = 1 << $j;
		my $res = $i & $mask;
		if ($res != 0) {
			$o .= sprintf("T%s", $offset[$j]);
		}
	}
	if ($0 ne "") {
		printf "%s\n", $o;
	}
	$o = "";
}
