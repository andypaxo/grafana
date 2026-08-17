package useractions

import (
	"context"
	"embed"
	"fmt"
	"text/template"

	claims "github.com/grafana/authlib/types"

	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/storage/legacysql"
	"github.com/grafana/grafana/pkg/storage/unified/sql/sqltemplate"
)

var (
	//go:embed *.sql
	sqlTemplatesFS embed.FS
	sqlTemplates   = template.Must(template.New("sql").ParseFS(sqlTemplatesFS, `*.sql`))

	sqlQueryActions = mustTemplate("actions_query.sql")
)

func mustTemplate(filename string) *template.Template {
	if t := sqlTemplates.Lookup(filename); t != nil {
		return t
	}
	panic(fmt.Sprintf("template file not found: %s", filename))
}

// ActionsQuery selects every role granting permissions to an identity: the
// identity's basic role (and Grafana Admin when it is a server admin), roles
// assigned directly to the user, and roles assigned to its teams.
type ActionsQuery struct {
	OrgID         int64
	UserID        int64
	TeamIDs       []int64
	Role          string
	IsServerAdmin bool
}

type getActionsQuery struct {
	sqltemplate.SQLTemplate
	Query *ActionsQuery

	PermissionTable  string
	UserRoleTable    string
	TeamRoleTable    string
	BuiltinRoleTable string
}

func (r getActionsQuery) Validate() error {
	return nil
}

func newGetActions(sql *legacysql.LegacyDatabaseHelper, q *ActionsQuery) getActionsQuery {
	return getActionsQuery{
		SQLTemplate:      sqltemplate.New(sql.DialectForDriver()),
		Query:            q,
		PermissionTable:  sql.Table("permission"),
		UserRoleTable:    sql.Table("user_role"),
		TeamRoleTable:    sql.Table("team_role"),
		BuiltinRoleTable: sql.Table("builtin_role"),
	}
}

// ActionStore lists the distinct RBAC actions granted to an identity.
type ActionStore interface {
	GetUserActions(ctx context.Context, ns claims.NamespaceInfo, query ActionsQuery) ([]string, error)
}

// SQLActionStore reads actions from the RBAC tables of the tenant database.
// It goes through legacysql so the same implementation serves single-tenant
// Grafana and the multi-tenant IAM apiserver, where the tables live in a
// per-tenant schema resolved from the request namespace.
type SQLActionStore struct {
	sql    legacysql.LegacyDatabaseProvider
	tracer tracing.Tracer
}

func NewSQLActionStore(sql legacysql.LegacyDatabaseProvider, tracer tracing.Tracer) *SQLActionStore {
	return &SQLActionStore{sql: sql, tracer: tracer}
}

func (s *SQLActionStore) GetUserActions(ctx context.Context, ns claims.NamespaceInfo, query ActionsQuery) ([]string, error) {
	ctx, span := s.tracer.Start(ctx, "iam.useractions.store.GetUserActions")
	defer span.End()

	sql, err := s.sql(ctx)
	if err != nil {
		return nil, err
	}

	query.OrgID = ns.OrgID
	req := newGetActions(sql, &query)
	q, err := sqltemplate.Execute(sqlQueryActions, req)
	if err != nil {
		return nil, err
	}

	rows, err := sql.DB.GetSqlxSession().Query(ctx, q, req.GetArgs()...)
	if err != nil {
		return nil, err
	}
	defer func() {
		if rows != nil {
			_ = rows.Close()
		}
	}()

	var actions []string
	for rows.Next() {
		var action string
		if err := rows.Scan(&action); err != nil {
			return nil, err
		}
		actions = append(actions, action)
	}

	return actions, rows.Err()
}
