#!/usr/bin/env perl -w
##
#
# Written by Mick Grove
# Last Updated: 12/19/2012
#
# Retrieve FireEye report (by MD5) for a smple, from an on-premise FireEye MAS 43XX appliance 
#   --- Tested with FireEye OS v6.1.x
##
use strict;

use warnings;
use Getopt::Long;
use LWP::UserAgent;
use HTML::Entities;
use HTML::TableContentParser;
use HTML::TreeBuilder;
use HTTP::Request::Common;
use XML::LibXSLT;
use XML::LibXML;
use Encode;
use FindBin;
use Config;

# Set-up resolver
my $cymru_res = Net::DNS::Resolver->new;
my %cymru_socket_hash;

my $username          = "<username>";
my $userpw            = "<pwd>";
my $FireEyeWebAddress = "https://internal.fireye.address.here:2020";
my $form_login_name_field   = "user[account]";
my $form_login_pwd_field    = "user[password]";
my $stylesheet_location     = "$FireEyeWebAddress/stylesheets/events.xsl";
my $css_stylesheet_location = "$FireEyeWebAddress/stylesheets/xml_style.css";
my $Chaosreader_FE_path     = "$FindBin::Bin/chaosreader.pl";
my $pcap_temp_dir           = "$FindBin::Bin/";                                 # change this to have pcap temporarily stored elsewhere
my $bReportCompleted        = undef;                                            #false
my $bAlertsCompleted        = undef;
$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;

#my $perl_binary = $^X;
my $perl_binary = $Config{perlpath};
$perl_binary .= $Config{_exe}
  if $^O ne 'VMS' and $perl_binary !~ /$Config{_exe}$/i;

#print "executable is $perl_binary\n";

#
my $req_md5;
my $output_dir;
my $help;

usage()
  if (
    @ARGV < 2
    or !GetOptions(
        "help|h|?"     => \$help,
        "md5=s"        => \$req_md5,
        "output_dir=s" => \$output_dir
    )
  ) or defined $help;

sub usage
{
    print "Unknown option: @_\n" if (@_);

    print "\nusage: \n\tFireEye_retrieve.pl --md5=ca72a0e171770ff63614a57d1f31f143 --output_dir=~/path/to/saved_reports/";
    exit;
}

$output_dir =~ s/\/$//;

if ( !-d $output_dir ) {
    mkdir($output_dir) || die "Unable to create directory <$!>\n";
}

my $max_size = 99_000_000;    #thats about 99mb
our $browser = LWP::UserAgent->new( agent => 'Mozilla/4.0 (compatible; MSIE 7.0)' );

push @{ $browser->requests_redirectable }, [ 'GET', 'HEAD', 'POST' ];
$browser->cookie_jar( {} );

eval {
    print "\n";
    RetrieveReportFromFireEye($req_md5);
};

if ($@) {
    print "\nThe following error occured while processing \"$req_md5\":\n$@\n";
    exit 1;
} else {
    exit 0;
}

#
#
#

sub RetrieveReportFromFireEye
{
    my ($md5) = shift;
    if ( !defined $md5 ) {
        print "\nNO MD5 received!";
        exit;
    }

    my $login_request = $browser->request( GET "$FireEyeWebAddress/login/login" );
    if ( !$login_request->is_success ) {
        print "Could not login.";
        exit;
    }

    $login_request = POST "$FireEyeWebAddress/login/login",
      [
        "$form_login_name_field" => $username,
        "$form_login_pwd_field"  => $userpw,
      ],
      'Content_Type' => 'form-data';    #'multipart/form-data';#

    my $res = $browser->request($login_request);
    sleep(1);

    #get the stylesheet
    $res = $browser->request( GET "$css_stylesheet_location" );
    if ( !$res->is_success ) {
        print "Could not retrieve CSS stylesheet page. Try again in 15 minutes.";
        exit 2;
    }

    my $the_cssstyle = "<style type=\"text/css\">\n" . $res->content . "\n<\/style>";

    $res = $browser->request( GET "$stylesheet_location" );
    if ( !$res->is_success ) {
        print "Could not retrieve XML stylesheet page. Try again in 15 minutes.";
        exit 2;
    }

    my $the_xmlstyle = $res->content;

    $res = $browser->request( GET "$FireEyeWebAddress/malware_analysis/analyses" );
    if ( !$res->is_success ) {
        print "Could not retrieve reports page. Try again in 15 minutes.";
        exit 2;
    }

    my $auth_token;

    if ( $res->content =~ m/^.*<input.*name=.*"authenticity_token".*value=.*"(.*)".*$/im ) {
        $auth_token = $1;
    }


    my $query = POST "$FireEyeWebAddress/malware_analysis/update_filter", [
        'utf8' => '%E2%9C%93',
        'authenticity_token' => $auth_token,
        'filter' => 'Set',
        'ma_filter_text' => $md5,
        'ma_filter_col' => 'md5sum',
        'ma_username' => 'All',
      ], 'Content_Type' => 'application/x-www-form-urlencoded'; #'multipart/form-data'; #

    $res = $browser->request( $query );
    if ( !$res->is_success ) {
        print "Could not retrieve reports page. Try again in 15 minutes.";
        exit 2;
    }
       
    my @analysis_ids;

    ##

    @analysis_ids = GetAnalysisId( \$res );
    ##

    my $outFileName = $output_dir . "/" . $md5;
    my $toprint;
    my $outFile;
    my $curContent;
    my $xslt = XML::LibXSLT->new();

    foreach my $analysis_id (@analysis_ids) {
        if ( !defined $analysis_id ) { next }
        $res = $browser->request( GET "$FireEyeWebAddress/event_stream/events_in_xml?events=$analysis_id" );
        if ( !$res->is_success ) {
            next;

            #print "Sample not found. Try again in 15 minutes.";
            #exit 2;
        }

        $curContent = $res->content;
        my @malicious_alerts;
        @malicious_alerts = $curContent =~ m!^<malicious-alert.*<display-msg>(.*)</display-msg>.*$!img;

        if ( !@malicious_alerts ) {
            @malicious_alerts = $curContent =~ m!.*?<malicious-alert.*?<display-msg>(.*?)</display-msg>.*?!simxg;
        }
	

        my $source = XML::LibXML->load_xml( string => $curContent );

        my $style_doc  = XML::LibXML->load_xml( string => $the_xmlstyle, no_cdata => 1 );
        my $stylesheet = $xslt->parse_stylesheet($style_doc);
        my $results    = $stylesheet->transform($source);

        $curContent = $stylesheet->output_as_bytes($results);

        #this embeds our css stylesheet in the html page...meaning we only need 1 HTML file now
        $curContent =~ s!<link rel="stylesheet" type="text/css" href="\.\./stylesheets/xml_style\.css">!$the_cssstyle!img;

        # this will retrieve pcap file, parse it, and add it to the $toprint variable
        $toprint .= GetPcapData( \$curContent, \$res, \$browser, $md5, \@malicious_alerts );

        #$toprint .= $curContent;
        #print "\n\n\n$toprint";
    }

    if ($bReportCompleted) {
        if ( -f $outFileName . ".html" ) {
            unlink($outFileName);
        }

        $outFileName = $outFileName . ".html";    #add file extension
        open $outFile, '>', $outFileName or die "Failed opening $outFileName: $!";

        $toprint = encode_utf8($toprint);
        print $outFile $toprint;
        print "\n<" . $outFileName . ">";
        print "\nDone.\n";
    } else {
        print "\n*** error while writing report. It is not yet completed. Try again in 15 minutes.\n";
    }

    #exit;
}

sub GetPcapData
{
    my $ref_toprint = shift;
    my $toprint     = $$ref_toprint;

    #
    my $ref_res = shift;
    my $res     = $$ref_res;

    #
    my $ref_browser = shift;
    my $browser     = $$ref_browser;

    #
    my $md5 = shift;

    #
    my $ref_malicious_alerts = shift;
    my @malicious_alerts     = @{$ref_malicious_alerts};

    my $tree = HTML::TreeBuilder->new( api_version => 3 );
    $toprint = decode_utf8($toprint);
    $tree->parse($toprint);

    my $curHref;
    my $pcapUrl = "-";

    foreach my $ahref ( $tree->find_by_tag_name('a') ) {
        if ( !defined $ahref->attr('href') ) { next; }
        if ( $ahref->attr('href') !~ /^#/ ) {    #ignore anchors
            $curHref = $ahref->as_HTML();
            if ( !defined $curHref ) { next; }
            if ( $curHref =~ m!<a.*href="(.*)">.*</a>!im ) {
                if ( length($pcapUrl) <= 1 ) {
                    $pcapUrl = "$FireEyeWebAddress" . $1;
                    if ( $curHref =~ m/.*send_pcap_file\?.*/im ) {
                    } else {
                        $pcapUrl = "-";
                    }
                }
            }
        }
        $ahref->replace_with_content( $ahref->as_text );
    }

    my $bFoundBotComm = undef;    #false
    my $bCymruCompleted = undef;
    my $foundhost;
    my $bluecoat_category;

    foreach my $tdtag ( $tree->find_by_tag_name('td') ) {
        my $curtag = $tdtag->as_text;
        if ( !defined $bFoundBotComm ) {
            if ( $curtag =~ m/bot communication details/im ) {
                $bFoundBotComm = 1;    #true
            }
        }

        if ( !defined $bReportCompleted ) {
            if ( $curtag =~ m/^.*OS\sChange\sDetail\s.*/im ) {
                $bReportCompleted = 1;    #true
            } elsif ( $curtag =~ m/^.*Archived\sObject:.*/im ) {
                $bReportCompleted = 1;    #true
            } elsif ( $curtag =~ m/^.*VM\sCapture:.*/im ) {
                $bReportCompleted = 1;    #true
            } else {
                $bReportCompleted = undef;    #false
            }
        }

        if ( !defined $bAlertsCompleted ) {
            if (@malicious_alerts) {
                if ( $curtag =~ m/^.*Trace\sBookmark\sLink\:.*/im ) {
                    $tdtag->push_content( ['br'], [ 'a', {'href' => '#parsed_pcap'}, 'Jump to analysis of pcap network capture' ], ['br'] );
                    $tdtag->push_content( ['br'], [ 'h3', 'Summary of Malicious Alerts' ], ['ul'], map [ 'li', $_ ], @malicious_alerts );
                    $bAlertsCompleted = 1;
                }
            }
        }

        if ( !defined $bCymruCompleted ) {
            if ( $curtag =~ m/^.*Trace\sBookmark\sLink\:.*/im ) {
                process_hash($md5);
                my $cymru_result = collect_results();
                $tdtag->push_content("TEAM CYMRU => $cymru_result");
                $bCymruCompleted = 1;
            }
        }
    }

    if ( length($pcapUrl) > 1 ) {
        my $f;
        $res = $browser->request( GET "$pcapUrl" );
        if ( $res->is_success ) {
            $f = $pcap_temp_dir . $md5 . "\.pcap";
            print $f;
            open OUTPUT, ">", $f or print "Couldn't open ", $f, " for writing";
            print OUTPUT $res->content;
            close(OUTPUT);
        }

        my $chaosreader_output;
        $chaosreader_output = `$perl_binary $Chaosreader_FE_path $f --quiet --noipaddr 224.0.0.252,199.16.199.2,199.16.199.3,199.16.199.4,199.16.199.5,199.16.199.6,199.16.199.7,199.16.199.8,199.16.199.9,199.16.199.10,199.16.199.11 --noport 1049`;    # --noport 67,5355`;

        $toprint = $tree->as_HTML( undef, "\t" );
        $toprint .= $chaosreader_output . "<br><br><br>";
        unlink($f);
    }

    $tree = $tree->delete;
    return $toprint;
}

sub WalkTable
{
    my $ref_index_table = shift;
    my $index_table     = $$ref_index_table;
    my $analysis_id;

    foreach my $a ( @{ $index_table->{rows} } ) {
        $analysis_id = trim( $a->{cells}[1]{data} );
        decode_entities($analysis_id); #we have to decode html entities...from HTML::Entities
        if ( !defined $analysis_id ) { next; }
        if ( $analysis_id =~ m/render_event_cluster\('(.*)',.*/im ) {
            $analysis_id = $1;
        } else {
            $analysis_id = undef;
            next;
        }
    }
    return $analysis_id;
}

sub GetAnalysisId
{
    my $ref_res = shift;
    my $res     = $$ref_res;
    my $analysis_id;
    my @analyseez;
    my $tcp      = HTML::TableContentParser->new;
    my $curTable = 1;

    #retrieve tables
    my $tables      = $tcp->parse( $res->content() );
    my $index_table = $tables->[$curTable];             #grab the most recent sample

    $analysis_id = WalkTable( \$index_table );

    # this sees that this analysis id has no results. It could be because
    #   it is a zip file, so try and grab the files contained within it.
    if ( !defined $analysis_id ) {
        while ( defined $index_table ) {
            $curTable++;
            $index_table = $tables->[$curTable];

            if ( defined $index_table ) {
                $analysis_id = WalkTable( \$index_table );
                if ( defined $analysis_id ) {
                    push( @analyseez, $analysis_id );
                }
                $analysis_id = undef;
            }
        }
    } else {
        push( @analyseez, $analysis_id );
    }
    return @analyseez;
}

sub trim
{
    my $string = shift;

    if ( defined $string ) {
        $string =~ s/^\s+//;
        $string =~ s/\s+$//;
    }
    return $string;
}

sub process_hash
{
    my $digest = shift or return undef;

    if ( ( my ($sock) = dns_lookup($digest) ) ) {
        $cymru_socket_hash{$digest} = $sock;
    } else {
        print STDERR "Cymru Query [ERROR] Lookup error\n";
    }

}

sub dns_lookup
{

    my $cymru_service = 'hash.cymru.com';
    my ($hash) = shift or return undef;

    #my $sock = $cymru_res->bgsend( "$hash.$cymru_service.", 'A' );
    my $sock = $cymru_res->bgsend( "$hash.$cymru_service.", 'TXT' );
    if ($sock) {
        return $sock;
    } else {
        print STDERR "Cymru Query [ERROR] failed ", $cymru_res->errorstring, "\n";
        return undef;
    }
}

sub collect_results
{
    my $RetMsg;
    my $cymru_timeout = 30;

    #eval {

    # Set-up timeout
    local $SIG{ALRM} = sub { die "timeout"; };
    alarm($cymru_timeout);

    # Loop through DNS sockets
    until ( ( my $count = scalar keys %cymru_socket_hash ) == 0 ) {
        ## print "Found $count sockets waiting\n";
        while ( ( my ( $file, $sock ) ) = each(%cymru_socket_hash) ) {
            next unless $cymru_res->bgisready($sock);
            ## print "Found socket ready for file $file\n";
            if ( ( my $packet = $cymru_res->bgread($sock) ) ) {

                # Close socket
                undef $sock;
                my $string;
                my $unixtime;
                my $standardtime;
                my $percent;

                # Process packet
                my $found = 0;
                foreach my $rr ( $packet->answer ) {

                    #if ( $rr->type eq 'A' && $rr->address eq '127.0.0.2' ) {
                    if ( $rr->type eq 'TXT' ) {    #' && $rr->address eq '127.0.0.2' ) {
                        $string = $rr->txtdata;
                        ( $unixtime, $percent ) = split( ' ', $string );
                        $standardtime = scalar localtime($unixtime);
                        $found        = 1;
                    }
                }
                if ($found) {

                    #print STDOUT "Cymru Query = [MALWARE]. Last seen [$standardtime]. AV detection rate = [$percent].\n";
                    $RetMsg = "[MALWARE]. Last seen [$standardtime]. AV detection rate = [$percent].\n";
                    return $RetMsg;
                } else {

                    #print STDOUT "Cymru Query = [NO_DATA] File: $file\n";
                    $RetMsg = "[NO_DATA]";    # File: $file\n";
                    return $RetMsg;
                }
            } else {

                $RetMsg = "Cymru Query [ERROR] " . $cymru_res->errorstring . "\n";
                return $RetMsg;
            }

            # Remove answer from hash
            delete $cymru_socket_hash{$file};
        }

        # Don't use excessive CPU
        sleep(1) if ( ( $count = scalar keys %cymru_socket_hash ) > 0 );
    }

    #};    # eval
    #if ($@) {
    #    if ( $@ =~ /timeout/ ) {
    #        #print STDERR "Cymru Query [ERROR] Timed out after $cymru_timeout seconds\n";
    #        return "Cymru Query [ERROR] Timed out after $cymru_timeout seconds\n";
    #    } else {
    #        #print $@;
    #        return $RetMsg;
    #    }
    #}
}
