import pytest

from app.database.roles import RolePlan, main, render_sql, runtime_grants_sql


@pytest.mark.parametrize('field,value', [
    ('database', 'other_database'), ('database', 'ai_soc; DROP DATABASE ai_soc'),
    ('schema', 'public; SELECT 1'), ('schema', 'x' * 64),
    ('runtime_role', 'postgres'), ('runtime_role', 'pg_dangerous'),
    ('owner_role', 'public'), ('migrator_role', 'has space'),
    ('runtime_role', 'ai_soc_owner'), ('owner_role', None),
])
def test_invalid_identifiers_or_role_overlap_rejected(field, value):
    with pytest.raises(ValueError): RolePlan(**{field: value})


def test_rendered_plan_is_transactional_guarded_and_contains_no_login_secret():
    sql = render_sql(RolePlan())
    assert sql.startswith('BEGIN;') and sql.rstrip().endswith('COMMIT;')
    assert 'current_database()' in sql and 'd93c6e4fb132' in sql
    assert 'NOLOGIN' in sql and 'NOSUPERUSER' in sql and 'NOBYPASSRLS' in sql
    assert 'PASSWORD' not in sql.upper()
    assert 'SECURITY DEFINER' not in sql.upper()
    assert 'WITH GRANT OPTION' not in sql.upper()


def test_runtime_profile_does_not_grant_mutable_history_or_keys():
    sql = '\n'.join(runtime_grants_sql(RolePlan()))
    grants = [line for line in sql.splitlines() if line.startswith('GRANT ')]
    for line in grants:
        if '"audit_logs"' in line or '"evidence_records"' in line:
            assert 'UPDATE' not in line and 'DELETE' not in line and 'TRUNCATE' not in line
        if '"tenant_api_keys"' in line:
            assert 'INSERT' not in line and 'UPDATE' not in line


def test_generator_cli_only_prints_sql_and_never_connects(monkeypatch, capsys):
    import sqlalchemy
    monkeypatch.setattr(sqlalchemy, 'create_engine', lambda *a, **k: pytest.fail('generator connected'))
    assert main([]) == 0
    assert capsys.readouterr().out.startswith('BEGIN;')


def test_invalid_cli_arguments_do_not_echo_values(capsys):
    with pytest.raises(SystemExit) as result:
        main(['--password', 'must-not-leak'])
    assert result.value.code == 2
    output = capsys.readouterr()
    assert 'must-not-leak' not in output.out + output.err
