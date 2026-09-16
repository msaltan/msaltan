package trino

import rego.v1

default allow := false

# Trino sends the authenticated principal as input.context.identity.user.
# This policy intentionally ignores token claims, roles, and groups.
user := input.context.identity.user

operation := input.action.operation

resource := input.action.resource

# Unknown users resolve to an empty permission object and therefore deny.
permissions := object.get(data.trino.users, user, {})

# Helper for rules that need to check a catalog-level permission.
catalog_operation(catalog, requested_operation) if {
	permission := permissions.catalogs[_]
	permission.catalog == catalog
	requested_operation in permission.operations
}

schema_match(catalog, schema) if {
	permission := permissions.schemas[_]
	permission.catalog == catalog
	match_name(schema, permission.schema)
}

table_operation(catalog, schema, table, requested_operation) if {
	permission := permissions.tables[_]
	permission.catalog == catalog
	match_name(schema, permission.schema)
	match_name(table, permission.table)
	requested_operation in permission.operations
}

table_schema_operation(catalog, schema, requested_operation) if {
	permission := permissions.tables[_]
	permission.catalog == catalog
	match_name(schema, permission.schema)
	requested_operation in permission.operations
}

# "*" in data.json means any schema or table name at that level.
match_name(_, expected) if {
	expected == "*"
}

match_name(value, expected) if {
	value == expected
}

allow if {
	operation in permissions.base_operations
}

# Catalog operations use resource.catalog, for example AccessCatalog.
allow if {
	permission := permissions.catalogs[_]
	operation in permission.operations
	resource.catalog.name == permission.catalog
}

# Schema operations use resource.schema, for example ShowTables.
allow if {
	permission := permissions.schemas[_]
	operation in permission.operations
	resource.schema.catalogName == permission.catalog
	match_name(resource.schema.schemaName, permission.schema)
}

# A writer that can create tables in a schema can bootstrap the schema itself.
# This covers service-account loaders such as svc-trino-examples-writer.
allow if {
	operation == "CreateSchema"
	table_schema_operation(resource.schema.catalogName, resource.schema.schemaName, "CreateTable")
}

# Table operations use resource.table, for example SelectFromColumns.
allow if {
	permission := permissions.tables[_]
	operation in permission.operations
	resource.table.catalogName == permission.catalog
	match_name(resource.table.schemaName, permission.schema)
	match_name(resource.table.tableName, permission.table)
}

# BI tools such as Superset query information_schema through Trino for metadata
# discovery. Trino also runs filter checks around these metadata queries, so
# allow information_schema access for any catalog the user can access.
allow if {
	operation in ["SelectFromColumns", "ShowColumns", "FilterTables", "FilterColumns"]
	resource.table.schemaName == "information_schema"
	catalog_operation(resource.table.catalogName, "AccessCatalog")
}

allow if {
	operation in ["ShowTables", "FilterSchemas"]
	resource.schema.schemaName == "information_schema"
	catalog_operation(resource.schema.catalogName, "AccessCatalog")
}

allow if {
	operation == "FilterCatalogs"
	catalog_operation(resource.catalog.name, "AccessCatalog")
}

allow if {
	operation == "FilterSchemas"
	schema_match(resource.schema.catalogName, resource.schema.schemaName)
}

allow if {
	operation == "FilterTables"
	table_operation(resource.table.catalogName, resource.table.schemaName, resource.table.tableName, "SelectFromColumns")
}

allow if {
	operation == "FilterColumns"
	table_operation(resource.table.catalogName, resource.table.schemaName, resource.table.tableName, "ShowColumns")
}

allow if {
	operation == "FilterColumns"
	table_operation(resource.column.catalogName, resource.column.schemaName, resource.column.tableName, "ShowColumns")
}
