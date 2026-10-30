use strict;
use warnings;
use Test::More;
use Test::Exception;
use CGI::Simple;
use CGI::Simple::Cookie;

# Regression tests for header injection through cookie arrays and attributes.
# Unsafe output must raise an exception before it can become an HTTP header.
my $q = CGI::Simple->new('');

# Each cookie array element must be checked, for every supported option alias.
# CR/LF can introduce another header; NUL and DEL are also forbidden controls.
for my $control ( "\r\n", "\r", "\n", "\x00", "\x7f" ) {
  for my $option ( '-cookie', '-cookies', '-set-cookie' ) {
    throws_ok {
      $q->header( $option => [ 'safe=value', "id=x${control}X-Injected: yes" ] );
    } qr/Invalid cookie header value/, 'reject control in cookie array';
  }
  # Cookies must reject controls even when followed by whitespace, rather than
  # treating them as folded header values and silently changing the cookie.
  throws_ok {
    $q->header( -cookie => "id=x${control} X-Injected: yes" );
  } qr/Invalid cookie header value/, 'reject controls even before whitespace';
}

# Attribute setters must not bypass validation at serialization time. Check
# standalone cookie output as well as objects passed in a header cookie array.
# Semicolons can inject extra attributes, such as an attacker-chosen Domain.
for my $attribute ( 'path', 'domain', 'expires' ) {
  for my $bad ( "/\r\nX-Injected: yes", "/\rX: yes", "/\n X: yes",
                "/\x00", "/\x7f", '/; Domain=example.org' ) {
    my $cookie = CGI::Simple::Cookie->new( -name => 'id', -value => 'x' );
    $cookie->$attribute($bad);
    throws_ok { $cookie->as_string }
      qr/Invalid cookie attribute/, "reject unsafe $attribute in standalone output";
    throws_ok { $q->header( -cookie => [$cookie] ) }
      qr/Invalid cookie attribute/, "reject unsafe $attribute in cookie object array";
  }
}

# Cookie values may contain these characters because they are percent-encoded.
# Valid attributes and mixed arrays of strings and cookie objects must still
# produce separate Set-Cookie headers in the original order.
my $cookie = CGI::Simple::Cookie->new(
  -name => 'id', -value => "x\r\n;", -path => '/app',
  -domain => 'example.org', -expires => 'Wed, 01 Jan 2031 00:00:00 GMT',
  -secure => 1, -httponly => 1, -samesite => 'Lax',
);
like $cookie->as_string, qr/^id=x%0D%0A%3B; /,
  'cookie values remain safely percent encoded';
like $q->header( -cookie => [ 'first=1', $cookie, 'last=2' ] ),
  qr/Set-Cookie: first=1\r\nSet-Cookie: id=.*\r\nSet-Cookie: last=2\r\n/,
  'valid mixed cookie arrays retain separate headers and order';

done_testing;
