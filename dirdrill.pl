#!/usr/bin/env perl
#
# author: Mick Grove
# Date: August 2003

#********************************************************************
#
# This script will accept a path as input, and drill down 1 level and
# output the folder names and their sizes. An error log will also be
# created. If a "users" folder is found, the script will drill down into
# it and output the folder names and their sizes as well.
#
# This script does not use File::Find because that module
# will end the script when it reaches a UNC path > 240 characters.
#
#********************************************************************

use strict;
use Time::localtime;
use File::Spec;

my $cur = File::Spec->curdir;
my $up  = File::Spec->updir;

my (
    $dir,      @parts,       $error,           $starttime,
    $runtime,  $endtime,     $runmin,          $year,
    $month,    $day,         $tm,              $date,
    $topdir,   $foldername,  $slash2,          $count,
    $runhour,  $starttime,   $runtime,         $endtime,
    $runmin,   $year,        $month,           $day,
    $tm,       $date,        $file,            $path_length,
    $totsize,  $warn1,       $warn2,           $path_length,
    $drilldir, $drilltopdir, $drillfoldername, $slash3,
    $lcasefoldername
);

$starttime = (time);
$slash2    = "//";
$slash3    = "///";

#############################################
#											#
#  Opens the input, output, and error log   #
#											#
#############################################
#open(IN, "< DirDrill_and_users_input.txt") or die("Couldn't open DirDrill_and_users_input.txt\n");
open( OUT, ">", "dirdrill-output.csv" )
  or die("Couldn't open dirdrill-output.csv\n");
open( ERRORLOG, ">", "dirdrill-errorlog.csv" )
  or die("Couldn't open dirdrill-errorlog.csv\n");

$warn1 = "WARNING - Path too long: ";
$warn2 = "WARNING! - Access to path was denied: ";

@parts = $ARGV[0];

#Separates the newline delimited rows
chomp( @parts = <IN> );

#Used to calculate how long the program took to run
$starttime = (time);

#Calculates the date
$tm    = localtime;
$year  = $tm->year + 1900;
$month = $tm->mon + 1;
$day   = $tm->mday;
$date  = "$month-$day-$year";

#Prints headings
print OUT "Path,Folder,MB,Date: $date\n";

#############################################
#											#
#    Calls subroutines, calculates date		#
#											#
#############################################
#foreach my $start (@parts) {
my $start;

my @dirs = &find_subdirs($start);
foreach my $dir (@dirs) {

    ( $topdir, $foldername ) = split /$slash2/, $dir;
    print "\tWalking $dir\n";
    $lcasefoldername = $foldername;
    $lcasefoldername =~ tr/A-Z/a-z/;

   # This large segment of code looks for a "users" directory, and if found it
   # will drill down into it and print out the usernames and the sizes of their
   # folders. If the current directory is not "users", or "users" doesn't exist,
   # then it is skipped and regular operation continues

    if ( $lcasefoldername eq "users" ) {
        $drilldir = $dir;
        foreach my $drillstart ($drilldir) {
            my @drilldirs = &find_drill_subdirs($drillstart);
            foreach my $drilldir (@drilldirs) {
                ( $drilltopdir, $drillfoldername ) = split /$slash3/, $drilldir;
                dodir($drilldir);
                $totsize = ( ( $totsize / 1024 ) / 1024 );    #Converts to MB
                $totsize =
                  sprintf( "%0.3f", $totsize );    #Formats to 3 decimal places
                $totsize = abs($totsize);
                print OUT"$drilltopdir,$drillfoldername,$totsize\n";
            }
        }
    }
    else {
        dodir($dir);

        $totsize = ( ( $totsize / 1024 ) / 1024 );    #Converts to MB
        $totsize = sprintf( "%0.3f", $totsize );    #Formats to 3 decimal places
        $totsize = abs($totsize);
        print OUT"$topdir,$foldername,$totsize\n";
    }
}

#}

#############################################
#											#
#    Calculates Run Time					#
#											#
#############################################
$endtime = (time);
$runtime = $endtime - $starttime;
$runmin  = $runtime / 60;
$runmin  = sprintf( "%0.1f", $runmin );
$runhour = $runmin / 60;
$runhour = sprintf( "%0.1f", $runhour );

if ( $runtime <= 60 ) {
    print "\n\nCompleted processing in $runtime seconds\n\n";
}
elsif ( $runmin <= 60 ) {
    print "\nCompleted processing in " . $runmin . " minutes\n\n";
}
else { print "\nCompleted processing in " . $runhour . " hours\n\n"; }

#Closes the output and errorlog files
#It also sleeps for 5 seconds to allow the output files
# to finish writing in case they haven't yet
sleep 5;
close(OUT);
close(ERRORLOG);
print "\tOutput created.";

#############################################
#											#
#    find_subdirs Subroutine				#
#											#
#############################################
sub find_subdirs {
    my $start = shift;
    unless ( opendir( D, $start ) ) {
        warn "$start: $!\n";
        next;

    }
    my @dirs =
      map {
        -d "$start/$_" && !-l "$start/$_" && $_ ne $cur && $_ ne $up
          ? "$start//$_"
          : ()
      } readdir(D);
    closedir(D);
    @dirs;
}
#############################################
#											#
#    dodir Subroutine						#
#											#
#############################################

sub dodir {
    opendir( DIR, $_[0] );
    my $dir2 = $_[0];
    if ( $dir2 !~ /\/$/ ) { $dir2 .= "/"; }

    my @List = readdir(DIR);
    closedir(DIR);
    splice( @List, 0, 2 );
    foreach $file (@List) {
        my $file = $dir2 . $file;
        if ( -d $file ) {
            dodir($file);
        }
        else {
            $totsize += ( -s $file );
        }
    }

    # This determines the length of the file path
    $path_length = length($dir2);

    #This determines if a path is longer than allowed by Windows OS
    # and it creates an error message if it is
    if ( $path_length > 238 ) { print ERRORLOG "$warn1,$dir2\n"; }

    #This determines if a path can't be accessed
    # and it creates an error message if it can't
    # NOTE: use only "$^E" or this will not work!
    if ( $^E eq "Access is denied" ) { print ERRORLOG "$warn2,$dir2\n"; }
}

#############################################
#											#
#    find_drill_subdirs Subroutine			#
#											#
#############################################
sub find_drill_subdirs {
    my $drillstart = shift;
    print "\n\tDeep Scanning: $drillstart\n\n";
    unless ( opendir( DM, $drillstart ) ) {
        warn "$drillstart: $!\n";
        next;

    }
    my @drilldirs =
      map {
        -d "$drillstart/$_" && !-l "$drillstart/$_" && $_ ne $cur && $_ ne $up
          ? "$drillstart///$_"
          : ()
      } readdir(DM);
    closedir(DM);
    @drilldirs;
}
