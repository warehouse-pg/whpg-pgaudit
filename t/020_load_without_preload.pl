#-------------------------------------------------------------------------------
# WHPG: loading pgaudit without shared_preload_libraries must fail cleanly, any
# number of times.
#
# pgaudit refuses to load unless it is preloaded.  A load that fails is not
# remembered, so it can be tried again in the same session.  The WarehousePG
# GPORCA layer installs planner and ExecutorStart hooks at load time; if a
# failed load left them installed, a second attempt would chain the hooks to
# themselves and the next statement would recurse until the backend crashed.
#
# The regression test cannot cover this because it needs pgaudit preloaded.
#-------------------------------------------------------------------------------

use strict;
use warnings FATAL => 'all';
use Test::More;

use PostgreSQL::Test::Cluster;

# A coordinator node without pgaudit in shared_preload_libraries.  On a segment
# pgaudit returns from its initialization before the preload check.
my $node = PostgreSQL::Test::Cluster->new('nopreload', coordinator => 1);

$node->init;
$node->start;

# One session: try to load twice, then run statements through the planner and
# the executor.
my ($ret, $stdout, $stderr) = $node->psql(
    'postgres', q{
LOAD 'pgaudit';
LOAD 'pgaudit';
SELECT 'query ' || count(*) FROM pg_class WHERE relname = 'pg_class';
CREATE TABLE load_test (id int);
INSERT INTO load_test VALUES (1);
SELECT 'rows ' || count(*) FROM load_test;
},
    on_error_stop => 0);

my $errors = () = $stderr =~ /pgaudit must be loaded via shared_preload_libraries/g;

is($errors, 2, 'both load attempts fail with the preload error');
is($ret, 0, 'the session survives the failed loads');
like($stdout, qr/^query 1$/m, 'a query runs after the failed loads');
like($stdout, qr/^rows 1$/m, 'DDL and DML run after the failed loads');

# A new session is unaffected as well
is($node->safe_psql('postgres', 'SELECT 1'), '1', 'a new session works');

$node->stop;

done_testing();
