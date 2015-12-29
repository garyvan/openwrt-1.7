#!/usr/bin/perl -w
use strict;
use warnings;
use Fatal qw/:void open opendir/;

foreach my $category (@ARGV) {
    my $functions = get_functions($category);
    build_category($category, $functions);
}

sub build_category {
    my ($category, $functions) = @_;

    open(FILE, '>', $category . '.c');

    foreach my $file ('sf_snort_plugin_api.h') {
        print FILE "#include \"$file\"\n";
    }

    foreach my $file (sort keys %{$functions}) {
        foreach my $rule (sort keys %{ $functions->{$file} }) {
            print FILE "extern Rule $rule;\n";
        }
    }

    print FILE "Rule *rules[] = {\n";

    foreach my $file (sort keys %{$functions}) {
        foreach my $rule (sort keys %{ $functions->{$file} }) {
            print FILE "    &$rule,\n";
        }
    }
    print FILE "    NULL\n};\n";
    close FILE;
}

sub get_functions {
    my ($category) = @_;
    my %functions;

    opendir(DIR, '.');
    foreach my $file (grep { /^$category.*\.c$/ } readdir(DIR)) {
        my $code = strip_comments(slurp($file));
        while ($code =~ s/^\s*Rule\s+(\w+)\s*=\s*\{//sm) {
            my $func = $1;
            # ... skip over functions that are used in a LoopInfo struct.  Bleh.
            if ($code !~ /LoopInfo\s+\w+\s=\s*{\s*([^,]*,){5}\s*\&$func,/sm) {
                $functions{$file}{$func}++;
            }
        }
    }
    closedir DIR;
    return \%functions;
}

sub slurp {
    my ($file) = @_;
    open(FILE, '<', $file);
    local $/;
    return <FILE>;
}

# XXX - should be more robust...
sub strip_comments {
    my ($code) = @_;
    $code =~ s{
       /\* # Match the opening delimiter.
       .*? # Match a minimal number of characters.
       \*/ # Match the closing delimiter.
   }{}gsx;
    return $code;
}
