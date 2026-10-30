use strict;
use warnings;
use Test::More;
use Test::Exception;
use CGI::Simple;

# Regression tests for header injection through a saved charset. Applications
# normally use a fixed charset, so attacker control is unlikely in practice.
# If an application does accept an untrusted charset, however, CR/LF must not
# allow it to introduce additional response headers through Content-Type.
my $q = CGI::Simple->new('');
my $original_charset = $q->charset;

# Check the setter path and the explicit header option, including controls
# followed by whitespace. Invalid explicit input must not replace saved state.
for my $control ( "\r\n", "\r", "\n", "\x00", "\t", "\x7f" ) {
  for my $suffix ( 'X-Injected: yes', ' X-Injected: yes' ) {
    my $bad = "UTF-8${control}${suffix}";
    $q->charset($bad);
    throws_ok { $q->header() }
      qr/Invalid charset header value contains a control character/,
      'reject controls in saved charset';

    $q->charset('UTF-8');
    throws_ok { $q->header( -charset => $bad ) }
      qr/Invalid charset header value contains a control character/,
      'reject controls in explicit charset';
    is $q->charset, 'UTF-8', 'invalid explicit charset does not replace saved value';
  }
}

# Fixed charsets still work through either interface, and a valid explicit
# value can replace an invalid saved value.
$q->charset("UTF-8\r\nX-Injected: yes");
like $q->header( -charset => 'UTF-8' ),
  qr/Content-Type: text\/html; charset=UTF-8\r\n/,
  'valid explicit charset replaces invalid saved value';
like $q->header(), qr/Content-Type: text\/html; charset=UTF-8\r\n/,
  'valid saved charset is included in Content-Type';
$q->charset($original_charset);

done_testing;
