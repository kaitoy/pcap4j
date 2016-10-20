#!perl

use strict;
use warnings;
use utf8;

use Getopt::Long qw(GetOptions);
use FindBin qw($Script);
use Carp qw(croak carp);

my $class_name;
my $cast = "";
my $registry;
GetOptions(
  'h|help'          => sub { pr_help(); exit 0; },
  'cn|class-name=s' => \$class_name,
  'c|cast=s'        => \$cast,
  'r|registry'      => \$registry,
) or do { pr_help(); exit 1; };

if ((not $registry) and (not defined $class_name)) {
  pr_help();
  exit 1;
}

$cast = $cast ? "($cast) " : $cast;

while (my $line = <>) {
  chomp $line;

  next if length($line) == 0;

  my @cols = split /\t/, $line, 3;
  if (@cols > 1) {
    my $num = $cols[0];
    my $name = $cols[1];
    my $descr = $cols[2];

    my $var_name = uc $name;
    $var_name =~ s{ }{_}g;
    $var_name =~ s{-}{_}g;
    $var_name =~ s{\.}{_}g;
    if ($name =~ m{/}) {
      carp "$name: / is replaced with _.";
      $var_name =~ s{/}{_}g;
    }

    if ($registry) {
      print "    registry.put($var_name.value(), $var_name);\n",
    }
    else {
      print "  /**\n",
            $descr ? "   * $descr: $num\n" : "   * $name: $num\n",
            "   */\n",
            "  public static final $class_name $var_name\n",
            "    = new $class_name(",
            $cast,
            $num,
            $descr ? qq{, "$descr");\n\n} : qq{, "$name");\n\n};
    }
  }
  else {
    croak $line;
  }
}

sub pr_help {
  print << "_HELP_";
  Usage:  $Script [Options]

  Options
    -h|--help               : Show this usage.
    -cn|--class-name <name> : Class name.
    -c|--cast <cast>        : cast.
    -r|--registry           : registry.
_HELP_
}
