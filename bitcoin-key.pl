#!/usr/bin/env perl

use strict;
use warnings;

use Crypt::PK::ECC;
use Crypt::RIPEMD160;
use Digest::SHA qw(sha256);
use v5.14;

use bigint;
use integer;

sub key2wif()
{
    my $ver = shift;
    my $src = shift;
    my $sum = substr sha256(sha256($ver.$src)), 0, 4;
    return encode_base58(hex(unpack("H*","$ver$src$sum")));
}

sub pub2addr()
{
    my $pub = shift;
    my $hash= chr(0).Crypt::RIPEMD160->hash(sha256($pub));
    my $sum = substr sha256(sha256($hash)), 0, 4;
    my $dst = encode_base58(hex(unpack("H*","$hash$sum")));
    return '1'x(34-length($dst)) . $dst;
}

sub encode_base58()
{
    my $val = shift;
    my $dst = '';
    my @b58 = split '', "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    # 
    while( $val > 0 ){
	$dst = $b58[$val%58] . $dst;
	$val = int($val/58);
    }
    return $dst;
}


die "Usage: $0 [private key hex]" if @ARGV < 1 or $ARGV[0] !~ /^[0-9a-f]+$/i;

my $pk = Crypt::PK::ECC->new();
$pk->import_key_raw(pack("H*",'0'x(64-length($ARGV[0])).$ARGV[0]),'secp256k1');

my $pri = $pk->export_key_raw('private');
my $pub = $pk->export_key_raw('public');
my $pubc= $pk->export_key_raw('public_compressed');

say "PriKey:   ". unpack "H*", $pri;
say "PriWIF:   ". &key2wif( chr(0x80), $pri );
say "PriWIF-c: ". &key2wif( chr(0x80), $pri.chr(1) );
say "PubKey:   ". unpack "H*", $pub;
say "PubKey-c: ". unpack "H*", $pubc;
say "Addr:     ". &pub2addr( $pub );
say "Addr-c:   ". &pub2addr( $pubc );
