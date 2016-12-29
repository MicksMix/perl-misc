#!/usr/bin/env perl -w
##
#
# Written by Mick Grove
# Last Updated: 4/25/2012
#
# Submit suspicious files to on-premise FireEye MAS 43XX appliance 
#   --- Tested with FireEye OS v6.1.x
##
use strict;
use Getopt::Long;
use LWP::UserAgent;
use HTTP::Request::Common;

my $username          = "<username>";
my $userpw            = "<pwd>";
my $FireEyeWebAddress = "https://internal.fireye.address.here:2020";
my $os_profile        = "win7-sp1";
my $timeout_seconds       = "900";              #900 = 15 minutes
my $form_login_name_field = "user[account]";
my $form_login_pwd_field  = "user[password]";
$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;

#///////////////////////
#///////////////////////

my $file_name;
my $the_url;
my $help;

usage()
  if (
    @ARGV < 1
    or !GetOptions(
        "help|h|?" => \$help,
        "file=s"   => \$file_name,
        "url=s"    => \$the_url
    )
  ) or defined $help;

sub usage {
    print "Unknown option: @_\n" if (@_);
    print
"\nusage: \n\tFireEye_submit.pl --file ~/path/to/file/badfile.exe\n";
    exit;
}

my $max_size = 99_000_000;    #thats about 99mb
our $browser =
  LWP::UserAgent->new( agent => 'Mozilla/4.0 (compatible; MSIE 7.0)' );
push @{ $browser->requests_redirectable }, 'POST';
$browser->cookie_jar( {} );

if ( !defined $file_name && !defined $the_url ) {
    print "\nYou must provide a file or URL!\n";
    usage();
}

if ( defined $file_name ) {
    if ( !-f $file_name ) {
        print "\n\"" . $file_name . "\" is not a file\. Exiting\.\n";
        exit;
    }

    if ( -s $file_name > $max_size ) {
        print "The maximum file size allowed is ", $max_size / 1_000_000,
          ". The \"$file_name\" exceeds this limit!\n";

        #next;
    }
    if ( -s $file_name == 0 ) {
        print "File \"$file_name\" has size zero. Will not be submitted.\n";

        #next;
    }
}
if ( defined $file_name ) {

    #don't die if an error occured, since this is a lengthy process
    #and we should process at least the files which we can
    eval {
        print "\nProcessing file \"$file_name\"\n";

        die("Tried to process element \"$file_name\" which is not a file!\n")
          if ( !-f $file_name );

        #print "\nSending to following sandbox Operating System(s):";
        #print "\n\t* Windows XP";

        SubmitFileToFireEye($file_name);
    };

    print "\nThe following error occured while processing \"$file_name\":\n$@\n"
      if ($@);

    print "\nDone.\n";
}

if ( defined $the_url ) {

    #don't die if an error occured, since this is a lengthy process
    #and we should process at least the files which we can
    eval {
        print "\nProcessing URL \"$the_url\"\n";

        SubmitUrlToFireEye($the_url);
    };

    print "\nThe following error occured while processing \"$the_url\":\n$@\n"
      if ($@);

    print "\nDone.\n";
}

sub SubmitUrlToFireEye {

    my ($url) = @_;

    my $login_request =
      $browser->request( GET "$FireEyeWebAddress/login/login" );
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

    if ( $res->is_success ) {
        print "\n======================\n";

        #print $res->decoded_content;    #
    }
    else {
        print "\n======================\n";
        die $res->status_line;
    }
    sleep(1);

    $res =
      $browser->request( GET "$FireEyeWebAddress/malware_analysis/analyses" );
    if ( !$res->is_success ) {
        print "Could not retrieve reports page. Try again in 15 minutes.";
        exit 2;
    }

    my $auth_token;

    if ( $res->content =~
        m/^.*<input.*name=.*"authenticity_token".*value=.*"(.*)".*$/im )
    {
        #extract auth token from page...we will use it for POST
        $auth_token = $1;
    }

    my $url_upload_request =
      POST "$FireEyeWebAddress/malware_analysis/add_analysis", [
        'authenticity_token' => $auth_token,
        'ma[analysis_type]'  => "Live",          #"Sandbox",
        'mw_source'          => "url",
        'url'                => $url,
        'timeout'            => $timeout_seconds,
        'ma[priority]'       => "Normal",
        'rp_profile'         => "$os_profile",
        'utf8'               => "✓",
        'browser' => 23,  #23 = Internet Explorer 8.0 --- works with XP sp3 only
        'de_profile' => $os_profile,    #"win7-base-de",
        'force'      => "1",            #1 = FORCE
        'prefetch'   => "1",
      ],
      'Content_Type' => 'multipart/form-data';    #

    $res = $browser->request($url_upload_request);
}

sub SubmitFileToFireEye {

    my ($file_name) = @_;

    my $login_request =
      $browser->request( GET "$FireEyeWebAddress/login/login" );
    if ( !$login_request->is_success ) {
        print "Could not login.";
        exit;
    }

    $login_request = POST "$FireEyeWebAddress/login/login",
      [
        "$form_login_name_field" => $username,
        "$form_login_pwd_field"  => $userpw,
      ],
      'Content_Type' => 'form-data';

    my $res = $browser->request($login_request);

    if ( $res->is_success ) {
        print "\n======================\n";
    }
    else {
        print "\n======================\n";
        die $res->status_line;
    }
    sleep(1);

    $res =
      $browser->request( GET "$FireEyeWebAddress/malware_analysis/analyses" );
    if ( !$res->is_success ) {
        print "Could not retrieve reports page. Try again in 15 minutes.";
        exit 2;
    }

    my $auth_token;

    if ( $res->content =~
        m/^.*<input.*name=.*"authenticity_token".*value=.*"(.*)".*$/im )
    {
        $auth_token = $1;
    }

    my $file_upload_request =
      POST "$FireEyeWebAddress/malware_analysis/add_analysis", [
        'authenticity_token' => $auth_token,
        'ma[analysis_type]'  => "Live",             #"Sandbox",
        'mw_source'          => "file",
        'file'               => [$file_name],
        'timeout'            => $timeout_seconds,
        'ma[priority]'       => "Urgent",           #"Normal",
        'win7-sp1_app'       => "",
        'rp_profile'         => "$os_profile",
        'utf8'               => "?",
        'de_profile'         => "$os_profile",      #"winxp-sp3",
        'force'              => "1",                #1 = FORCE
        'prefetch' => "1",
      ],
      'Content_Type' => 'multipart/form-data';    #

    $res = $browser->request($file_upload_request);
}

=cut

BROWSER values:

23 = Internet Explorer 8.0
25 = RealPlayer SP 11.0
32 = Adobe Reader 9.0
53 = QuickTime Player 7.5
57 = Windows Explorer
61 = Firefox 3.6
67 = Windows Media Player 12.0
68 = MS Word 2010
69 = MS Excel 2010
70 = MS PowerPoint 2010
