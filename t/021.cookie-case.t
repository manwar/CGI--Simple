use strict;
use warnings;
use Test::More tests => 33;
use Test::NoWarnings;
use CGI::Simple::Cookie;

foreach my $case (
  [ samesite => 'SameSite', qw(Strict Lax None) ],
  [ priority => 'Priority', qw(Low Medium High) ],
) {
  my ( $method, $attribute, @values ) = @$case;
  my $cookie = CGI::Simple::Cookie->new( -name => 'test', -value => 'value' );

  ok( !defined $cookie->$method(), "$attribute is initially unset" );
  foreach my $value ( @values ) {
    is( $cookie->$method( uc( $value ) ), $value,
      "$attribute normalizes uppercase $value" );
    is( $cookie->$method( lc( $value ) ), $value,
      "$attribute normalizes lowercase $value" );
    my $mixed = lc( substr( $value, 0, 1 ) ) . uc( substr( $value, 1 ) );
    is( $cookie->$method( $mixed ), $value,
      "$attribute normalizes mixed-case $value" );
    like( $cookie->as_string, qr/; $attribute=$value(?:;|$)/,
      "$attribute serializes as $value" );
  }
  is( $cookie->$method( 'invalid' ), $values[-1],
    "$attribute ignores invalid values" );
  is( $cookie->$method( '' ), $values[-1],
    "$attribute ignores empty values" );
  is( $cookie->$method(), $values[-1],
    "$attribute getter preserves the value" );
}
