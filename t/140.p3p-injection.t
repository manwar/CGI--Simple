use strict;
use warnings;
use Test::More;
use Test::Exception;
use CGI::Simple;

# Regression tests for header injection through P3P compact policy values.
# Previously, an array reference was checked before its elements were joined,
# allowing an element containing CR/LF to introduce an additional HTTP header.
my $q = CGI::Simple->new('');

# Check controls in every array position and in scalar input. Also reject
# controls before whitespace instead of silently unfolding the policy value.
for my $control ( "\r\n", "\r", "\n", "\x00", "\t", "\x7f" ) {
  for my $suffix ( 'X-Injected: yes', ' X-Injected: yes' ) {
    my $bad = "NOI${control}${suffix}";
    for my $value ( $bad, [$bad, 'DSP'], ['NOI', $bad] ) {
      throws_ok { $q->header( -p3p => $value ) }
        qr/Invalid P3P header value contains a control character/,
        'reject controls in scalar and array P3P values';
    }
  }
}

# Valid scalar and array policies must retain the existing header format.
my @policy = ('NOI', 'DSP');
my $expected = 'P3P: policyref="/w3c/p3p.xml", CP="NOI DSP"' . $q->crlf;
for my $value ( 'NOI DSP', \@policy ) {
  like $q->header( -p3p => $value ), qr/\Q$expected\E/,
    'valid P3P policy retains its header format';
}
is_deeply \@policy, ['NOI', 'DSP'], 'header generation leaves input array intact';

done_testing;
