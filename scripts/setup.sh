#!/usr/bin/env bash
echo "#######################################################"
echo "Starting to create environment for obfuscation analysis"
echo "#######################################################"
echo ""
echo "Checking System"
echo "---------------"
if which apptainer > /dev/null 2>&1 && which curl > /dev/null 2>&1
then
    echo "All requirements present "
    echo -n "Done "
    /usr/bin/printf "\xE2\x9C\x94\n\n"
else
    echo "System check failed, please install curl and apptainer (formerly known as singularity)"
    echo "Further information can be found at https://apptainer.org/"
    exit 1
fi
echo "Preparing database"
echo "------------------"
set -o pipefail
if ls db1.check > /dev/null 2>&1
then
    echo "Skipping container download"
else
    echo "--"
    if apptainer pull postgres.sif docker://postgres:15.4 2>&1 | grep -e "INFO:" -e "FATAL:" -e "WARNING:"
    then
        echo "--"
        mkdir postgresql
        mkdir postgresql/data
        mkdir postgresql/run
        touch db1.check
        echo "Retrieved postgresql image "
    else
        echo "Failed to retrieve postgresql image"
        exit 1
    fi
fi
if ls postgresql/data/postmaster.pid > /dev/null 2>&1
then
    echo "WARNING: Another postgres instance seems to be running already. If this is a local instance you use for other purposes than our tool, the next commands will probably fail and you need to adapt them to your database."
else
    apptainer run --env "POSTGRES_HOST_AUTH_METHOD=trust" --bind postgresql/data:/var/lib/postgresql/data --bind postgresql/run:/var/run/postgresql postgres.sif >> postgresql/server.log 2>&1 &
    sleep 5
    echo "Started postgresql container "

fi
if ls db2.check > /dev/null 2>&1
then
    echo "Skipping database creation"
    echo ""
else
    echo "create database malware;" > tmp.sql
    echo "--"
    if apptainer exec postgres.sif psql -U postgres -h 0.0.0.0 -p 5432 -f tmp.sql -v "ON_ERROR_STOP=1"
    then
        echo "--"
        rm tmp.sql
        touch db2.check
        echo "Created database "
    else
        rm tmp.sql
        echo "Failed to create database"
        exit 1
    fi
    echo -n "Done "
    /usr/bin/printf "\xE2\x9C\x94\n\n"
fi
echo "Retrieving analysis tool"
echo "------------------------"
if ls analysis.check > /dev/null 2>&1
then
    echo "Skipping analysis container file download"
    echo ""
else
    if curl -o analysis.def "https://raw.githubusercontent.com/NoahMauthe/ObA/main/environment/analysis.def" > /dev/null 2>&1
    then
        touch analysis.check
        echo -n "Done "
        /usr/bin/printf "\xE2\x9C\x94\n\n"
    else
        echo "Getting the analysis container file failed"
        exit 1
    fi
fi
echo "Building analysis container"
echo "---------------------------"
echo "--"
if apptainer build analysis.sif analysis.def 2>&1 | grep -e "INFO:" -e "FATAL:"
then
    echo "--"
    echo -n "Done "
    /usr/bin/printf "\xE2\x9C\x94\n\n"
else
    echo "--"
    echo "Failed to build the analysis container"
    exit 1
fi
echo "Downloading run script"
echo "----------------------"
if curl -o analysis "https://raw.githubusercontent.com/NoahMauthe/ObA/main/scripts/analysis" > /dev/null 2>&1
then
    echo -n "Done "
    /usr/bin/printf "\xE2\x9C\x94\n\n"
else
    echo "Getting the analysis container file failed"
    exit 1
fi
echo "Cleaning up"
echo "-----------"
rm *.check > /dev/null 2>&1
rm analysis.def > /dev/null 2>&1
rm setup.sh > /dev/null 2>&1
echo -n "Done "
/usr/bin/printf "\xE2\x9C\x94\n\n"
echo "################################"
echo "Successfully completed all tasks"
echo "################################"
