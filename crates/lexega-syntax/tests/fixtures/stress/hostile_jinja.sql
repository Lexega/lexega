-- =============================================================================
-- HOSTILE JINJA GOLDEN TEST: Comments EVERYWHERE in Jinja-embedded SQL
-- =============================================================================
-- This file is the Jinja equivalent of hostile_all_stmts.sql
-- Every single token position has a comment to stress-test CST preservation
-- with Jinja templates. Both SQL comments (-- and /* */) and Jinja comments
-- ({# #}) are mixed throughout to verify ALL trivia survives formatting.
-- =============================================================================
-- ===========================================================================
-- SECTION 1: Basic Jinja Expressions with Comments
-- ===========================================================================
-- 1.1: Simple ref() with comments everywhere
{# Jinja comment before statement #} SELECT /* c1 */ * /* c2 */ 
FROM /* c3 */ {{ ref('stg_orders') }} /* c4 */ ;
-- 1.2: source() macro with aggressive commenting
-- line comment before source
SELECT /* before cols */ id /* after id */ , /* before name */ name /* after name */ 
FROM /* before source */ {{ source('raw', 'customers') }}
/* after source */ WHERE /* before cond */ active /* after active */ = /* before val */ TRUE /* after val */ ;
-- 1.3: Variable substitution with mixed comment types
{# This Jinja comment describes the column selection #} SELECT /* block before jinja */ {{ column_name }} /* block after jinja */ , 
-- line comment mid-select
{# jinja comment mid-select #} {{ another_column }} AS /* alias comment */ col_alias
FROM {{ table_name }} /* table comment */ ;
-- 1.4: config() block with surrounding comments
-- SQL comment before config
{# Jinja comment describing config #} {{ config(materialized='table', schema='analytics') }}
/* after config */ 
-- SQL comment after config
SELECT /* select after config */ 1 /* literal comment */ AS /* as kw */ value /* col name */ ;
-- 1.5: dbt_utils with comments
SELECT
    /* before id */ id /* after id */ ,
    {# star macro generates all columns #} {{ dbt_utils.star(from=ref('orders')) }} /* after star */ ,
    -- timestamp column
    created_at /* after timestamp */ 
FROM /* from kw */ {{ ref('orders') }} /* after table ref */ ;
-- ===========================================================================
-- SECTION 2: Jinja Comments Mixed with SQL Comments
-- ===========================================================================
-- 2.1: All comment types in one statement
{# jinja: this describes the query purpose #} 
-- SQL line: this is the orders query
/* SQL block: selects all orders */ SELECT /* inline block */ *
{# inline jinja #} FROM orders /* after from */ -- trailing line
;
-- 2.2: Nested comment styles
/* outer block start 
   {# this looks like jinja but is inside SQL block #}
   -- this looks like line comment but is in block
   outer block end */ SELECT /* a */ 1 /* b */ ;
-- 2.3: Multi-line Jinja comment with SQL comments nearby
-- SQL before multi-line jinja
{# 
   Multi-line Jinja comment
   spanning several lines
   with context about the query below
   -- this is NOT a SQL comment, it's inside Jinja comment
#} 
-- SQL after multi-line jinja
SELECT /* c1 */ * /* c2 */ 
FROM /* c3 */ users /* c4 */ ;
-- 2.4: Alternating comment types
{# jinja1 #} -- sql1
/* block1 */ {# jinja2 #} 
-- sql2
{# jinja3 #} SELECT /* mixed */ 1 {# inline-j #} AS /* kw */ x -- trailing;
;
-- ===========================================================================
-- SECTION 3: {% if %} Blocks with Comments
-- ===========================================================================
-- 3.1: if block with comments at every position
{# decides if email should be included #} SELECT /* before jinja */ {% if include_email %}
    /* after if */ email /* col */ ,
/* comma */ {% endif %} /* after endif */ 
-- name is always included
{# name column next #} name /* after name */ 
FROM /* from kw */ users /* tbl */ ;
-- 3.2: if-else with comments in both branches
/* if-else statement */ {# chooses environment #} SELECT /* sel */ * /* star */ 
FROM /* from */ {% if is_prod %} /* prod branch */ production /* prod tbl */ {% else %} /* else branch */ development /* dev tbl */ {% endif %} /* after endif */ . /* dot */ orders /* orders */ ;
-- 3.3: if-elif-else with maximum commenting
{# environment selection logic #} SELECT /* sel kw */ * /* star */ 
FROM /* from kw */ {% if env == 'prod' %} /* prod */ prod_schema /* p_s */
    {% elif env == 'staging' %} /* staging */ staging_schema /* st_s */
    {% elif env == 'dev' %} /* dev */ dev_schema /* d_s */
    {% else %} /* else */ sandbox_schema /* sb_s */
    {% endif %} /* endif */ . /* dot */ orders /* tbl */ 
WHERE /* where */ 1 /* one */ = /* eq */ 1 /* one2 */ ;
-- 3.4: Multiple elif with comments in expression results
SELECT /* sel */ 
    {% if priority == 1 %}
        /* p1 */ 'Critical' /* v1 */ 
    {% elif priority == 2 %}
        /* p2 */ 'High' /* v2 */ 
    {% elif priority == 3 %}
        /* p3 */ 'Medium' /* v3 */ 
    {% elif priority == 4 %}
        /* p4 */ 'Low' /* v4 */ 
    {% elif priority == 5 %}
        /* p5 */ 'Trivial' /* v5 */ 
    {% else %}
        /* pX */ 'Unknown' /* vX */ 
    {% endif %} /* end */ AS /* as */ priority_label /* alias */ 
FROM /* from */ tickets /* tbl */ ;
-- ===========================================================================
-- SECTION 4: {% for %} Loops with Comments
-- ===========================================================================
-- 4.1: Simple for loop with comments at every position
{# iterates over columns #} SELECT /* sel */ {% for col in columns %}
    {# loop start #} /* before col */ {{ col }} /* after col */ {% if not loop.last %} /* comma cond */ , /* the comma */ {% endif %}
{# comma logic #} {% endfor %}
/* after endfor */ FROM /* from */ {{ ref('source') }} /* source ref */ ;
-- 4.2: For loop with loop.index and comments
-- loop with indexing
SELECT /* sel kw */ {% for col in columns %}
    /* loop {{ loop.index }} */ {{ col }} /* col val */ AS /* as kw */ col_ /* prefix */ 
    {{ loop.index }} /* idx */ {% if not loop.last %} /* if not last */ , /* sep */ {% endif %}
{% endfor %}
{# end columns loop #} FROM /* from kw */ source /* src tbl */ ;
-- 4.3: For loop with first/last checks
{# UNION ALL generator #} {% for table in tables %}
{# table loop #} /* table: {{ table }} */ {% if not loop.first %}
/* not first */ UNION /* union */ ALL /* all */ 
{% endif %}
/* after union check */ SELECT /* sel */ '{{ table }}' /* tbl name */ AS /* as */ source_table /* alias */ , /* comma */ * /* star */ 
FROM /* from */ {{ ref(table) }}
/* ref */ {% endfor %} /* endfor */ ;
-- 4.4: For loop generating WHERE conditions with comments
{# status filter generator #} SELECT /* sel */ * /* star */ 
FROM /* from */ orders /* tbl */ 
WHERE /* where */ 
    {% for status in valid_statuses %}
        /* status loop */ /* status: {{ status }} */ status /* col */ = /* eq */ '{{ status }}' /* val */ {% if not loop.last %} /* not last */ OR /* or kw */ {% endif %}
    {% endfor %} /* endfor */ ;
-- ===========================================================================
-- SECTION 5: {% set %} Statements with Comments
-- ===========================================================================
-- 5.1: Simple set with comments
{# define schema name #} {% set schema_name = 'analytics' %}
/* after set */ 
-- use the schema
SELECT /* sel */ * /* star */ 
FROM /* from */ {{ schema_name }} /* schema */ . /* dot */ orders /* tbl */ ;
-- 5.2: Set with expression and comments
-- date filter setup
{# computes month start #} {% set date_filter = "DATE_TRUNC('month', CURRENT_DATE)" %}
/* after set */ SELECT /* sel */ * /* star */ 
FROM /* from */ orders /* tbl */ 
WHERE /* where */ created_at /* col */ >= /* ge */ {{ date_filter }} /* filter val */ ;
-- 5.3: Set with list and for loop
{# metrics list definition #} {% set metrics = ['revenue', 'cost', 'profit'] %}
/* after metrics set */ SELECT /* sel */ {% for m in metrics %}
    {# metric loop #} SUM /* agg */ ( /* open */ {{ m }} /* metric */ ) /* close */ AS /* as */ total_ /* prefix */ 
    {{ m }} /* name */ {% if not loop.last %} /* sep check */ , /* comma */ {% endif %}
{% endfor %}
/* endfor */ FROM /* from */ sales /* tbl */ ;
-- 5.4: Set with dictionary and iteration
-- column mapping
{# legacy to current mapping #} {% set column_map = {'old_id': 'legacy_id', 'new_id': 'current_id'} %}
/* after set */ SELECT /* sel */ {% for old , new in column_map . items ( ) %}
    /* mapping loop */ {{ old }} /* old name */ AS /* as */ {{ new }} /* new name */ {% if not loop.last %} /* not last */ , /* comma */ {% endif %}
{% endfor %}
/* endfor */ FROM /* from */ mapping_table /* tbl */ ;
-- ===========================================================================
-- SECTION 6: Nested Control Flow (2 levels) with Comments
-- ===========================================================================
-- 6.1: If inside if with comments
{# double-if for status filtering #} SELECT /* sel */ * /* star */ 
FROM /* from */ orders /* tbl */ 
WHERE /* where */ 1 /* lit */ = /* eq */ 1 /* lit2 */ {% if filter_by_status %} {# outer if #} /* checking status filter */ {% if status == 'active' %} {# inner if active #} /* and */ AND status /* col */ = /* eq */ 'active' /* val */ AND /* and2 */ is_verified /* col2 */ = /* eq2 */ TRUE /* val2 */ {% else %} /* inner else */ /* and3 */ AND status /* col3 */ = /* eq3 */ '{{ status_forjinjatest }}' /* dynamic val */ {% endif %} /* inner endif */ {% endif %} /* outer endif */ ;
-- 6.2: For inside if with comments
{# conditional column expansion #} SELECT /* sel */ 
    id /* id col */ ,
    {% if include_details %}
        /* if details */ {# loop over detail columns #} {% for detail_col in ['description', 'category', 'tags'] %}
            /* detail loop */ {{ detail_col }} /* col */ {% if not loop.last %} /* comma? */ , /* sep */ {% endif %}
        {% endfor %}
    /* endfor */ {% else %}
        /* else no details */ 'REDACTED' /* redact val */ AS /* as */ details /* alias */ 
    {% endif %}
/* endif */ FROM /* from */ items /* tbl */ ;
-- 6.3: If inside for with comments
{# column transformation loop #} SELECT /* sel */ {% for col in columns %}
    /* col loop */ /* processing {{ col.name }} */ {% if col.is_nullable %}
        {# nullable check #} COALESCE /* fn */ ( /* open */ {{ col.name }} /* col */ , /* sep */ 'N/A' /* default */ ) /* close */ AS /* as */ {{ col.name }}
    /* alias */ {% else %}
        /* not nullable */ {{ col.name }}
    /* raw col */ {% endif %} /* endif */ {% if not loop.last %} /* comma check */ , /* sep */ {% endif %}
{% endfor %}
/* endfor */ FROM /* from */ source_table /* tbl */ ;
-- 6.4: For inside for with comments
{# schema.table cross product #} {% for schema in schemas %}
/* schema loop */ {# tables in {{ schema }} #} {% for table in tables %}
/* table loop */ /* query for {{ schema }}.{{ table }} */ SELECT /* sel */ * /* star */ 
FROM /* from */ {{ schema }} /* schema */ . /* dot */ {{ table }} /* tbl */ ;
{% endfor %}
/* end table loop */ {% endfor %}
/* end schema loop */ 
-- ===========================================================================
-- SECTION 7: Triple+ Nesting with Comments
-- ===========================================================================
-- 7.1: Triple-nested if with comments everywhere
{# load type determination #} SELECT /* sel */ 
    {% if env == 'prod' %}
        /* prod env */ {# production environment #} {% if is_incremental() %}
            /* incr check */ {# incremental mode #} {% if var('full_refresh', false) %}
                /* full refresh? */ 'full_refresh_prod' /* val1 */ 
            {% else %}
                /* not full refresh */ 'incremental_prod' /* val2 */ 
            {% endif %}
        /* inner endif */ {% else %}
            /* not incremental */ 'initial_load_prod' /* val3 */ 
        {% endif %}
    /* mid endif */ {% else %}
        /* not prod */ 'non_prod' /* val4 */ 
    {% endif %} /* outer endif */ AS /* as */ load_type /* alias */ 
FROM /* from */ {{ this }} /* self-ref */ ;
-- 7.2: Triple-nested for with comments
{# privilege generator #} {% for db in databases %}
/* db loop: {{ db }} */ {# databases iteration #} {% for schema in schemas %}
/* schema loop: {{ schema }} */ {# schemas iteration #} {% for table in tables %}
/* table loop: {{ table }} */ /* granting on {{ db }}.{{ schema }}.{{ table }} */ GRANT /* grant */ SELECT /* priv */ ON /* on */ {{ db }} /* db */ . /* d1 */ {{ schema }} /* schema */ . /* d2 */ {{ table }} /* tbl */ TO /* to */ ROLE /* role kw */ reader /* role */;
{% endfor %}
/* end table */ {% endfor %}
/* end schema */ {% endfor %}
/* end db */ 
-- 7.3: Mixed deep nesting (if-for-if-for) with comments
{# regional sales union generator #} {% if generate_unions %}
/* unions enabled */ {# union generation active #} {% for region in regions %}
/* region: {{ region }} */ {% if region != 'UNKNOWN' %}
/* valid region */ {# valid region processing #} {% for year in years %}
/* year: {{ year }} */ /* {{ region }} - {{ year }} */ SELECT /* sel */ 
    '{{ region }}' /* reg lit */ AS /* as */ region /* alias */ , /* comma */ 
    {{ year }} /* year lit */ AS /* as2 */ year /* alias2 */ , /* comma2 */ 
    SUM /* agg */ ( /* o1 */ sales /* col */ ) /* c1 */ AS /* as3 */ total /* alias3 */ 
FROM /* from */ regional_sales /* tbl */ 
WHERE /* where */ region /* col */ = /* eq */ '{{ region }}' /* val */ AND /* and */ YEAR /* fn */ ( /* o2 */ sale_date /* col2 */ ) /* c2 */ = /* eq2 */ {{ year }}
/* val2 */ GROUP /* group */ BY /* by */ 1 /* pos1 */ , /* comma */ 2 /* pos2 */ 
{% if not loop.last %}
    /* year not last */ UNION /* union */ ALL /* all */ 
{% endif %}
{% endfor %}
/* end year loop */ {% endif %}
/* end valid region */ {% if not loop.last %}
/* region not last */ UNION /* union2 */ ALL /* all2 */ 
{% endif %}
{% endfor %}
/* end region loop */ {% endif %} /* end unions check */ ;
-- ===========================================================================
-- SECTION 8: Jinja in All SQL Clause Positions with Comments
-- ===========================================================================
-- 8.1: Jinja in FROM clause with comments
{# table selection based on archive flag #} SELECT /* sel */ * /* star */ 
FROM /* from */ {% if use_archive %} /* archive branch */ archive /* arch */ {% else %} /* current branch */ current /* curr */ {% endif %} /* endif */ . /* dot */ {{ table_name }} /* tbl var */ ;
-- 8.2: Jinja in JOIN clause with comments
{# optional join construction #} SELECT /* sel */ o /* alias */ . /* dot */ * /* star */ , /* comma */ c /* alias2 */ . /* dot2 */ name /* col */ 
FROM /* from */ orders /* tbl */ o /* alias */ {% if join_customers %}
/* customer join enabled */ JOIN /* join */ customers /* c tbl */ c /* c alias */ ON /* on */ o /* o alias */ . /* dot */ customer_id /* col */ = /* eq */ c /* c alias */ . /* dot2 */ id /* c col */ {% endif %} /* endif customers */ {% if join_products %}
/* product join enabled */ LEFT /* left */ JOIN /* join2 */ products /* p tbl */ p /* p alias */ ON /* on2 */ o /* o alias */ . /* dot3 */ product_id /* col2 */ = /* eq2 */ p /* p alias */ . /* dot4 */ id /* p col */ {% endif %} /* endif products */ ;
-- 8.3: Jinja in JOIN condition with comments
{# legacy ID support #} SELECT /* sel */ * /* star */ 
FROM /* from */ 
orders /* o tbl */ o /* o alias */ 
JOIN /* join */ customers /* c tbl */ c /* c alias */ ON /* on */ o /* o a */ . /* d1 */ customer_id /* col */ = /* eq */ 
{% if use_legacy_id %}
    /* legacy */ c /* c a */ . /* d2 */ legacy_id /* leg col */ 
{% else %}
    /* current */ c /* c a2 */ . /* d3 */ id /* cur col */ 
{% endif %} /* endif */ ;
-- 8.4: Jinja in WHERE clause with comments
{# dynamic filtering #} SELECT /* sel */ * /* star */ 
FROM /* from */ orders /* tbl */ 
WHERE /* where */ status /* col */ = /* eq */ 'active' /* val */ {% if min_amount %} /* min check */ /* and */ AND amount /* col2 */ >= /* ge */ {{ min_amount }} /* min val */ {% endif %} /* end min */ {% if max_amount %} /* max check */ /* and2 */ AND amount /* col3 */ <= /* le */ {{ max_amount }} /* max val */ {% endif %} /* end max */ {% if category %} /* cat check */ /* and3 */ AND category /* col4 */ = /* eq2 */ '{{ category }}' /* cat val */ {% endif %} /* end cat */ ;
-- 8.5: Jinja in GROUP BY with comments
{# dynamic grouping #} SELECT /* sel */ {% if group_by_region %}
    /* grp region */ region /* reg col */ ,
/* comma1 */ {% endif %} /* end grp region */ {% if group_by_category %} /* grp category */ category /* cat col */ , /* comma2 */ {% endif %} /* end grp cat */ SUM /* agg */ ( /* o1 */ amount /* col */ ) /* c1 */ AS /* as */ total /* alias */ 
FROM /* from */ sales /* tbl */ 
{% if group_by_region or group_by_category %}
/* has grouping */ GROUP /* group */ BY /* by */ 
{% if group_by_region %}
    /* grp reg */ region /* reg */ {% if group_by_category %} /* both? */ , /* sep */ {% endif %} /* end both */ 
{% endif %}
/* end grp reg */ {% if group_by_category %}
    /* grp cat */ category /* cat */ 
{% endif %} /* end grp cat */ {% endif %} /* end grouping */ ;
-- 8.6: Jinja in ORDER BY with comments
{# dynamic ordering #} SELECT /* sel */ * /* star */ 
FROM /* from */ products /* tbl */ 
ORDER /* order */ BY /* by */ 
{% if order_by_price %}
    /* price order */ price /* col */ {{ price_direction }} /* dir */, /* comma */ 
{% endif %}
/* end price */ {% if order_by_name %}
    /* name order */ name /* col2 */ ASC /* dir2 */, /* comma2 */ 
{% endif %} /* end name */ id /* fallback */ ;
-- 8.7: Jinja in LIMIT/OFFSET with comments
{# pagination #} SELECT /* sel */ * /* star */ 
FROM /* from */ items /* tbl */ 
ORDER /* order */ BY /* by */ created_at /* col */ DESC /* dir */ 
LIMIT /* limit */ {{ page_size }}
/* size var */ {% if offset_val %} /* has offset */ OFFSET /* offset */ {{ offset_val }} /* offset var */ {% endif %} /* end offset */;
-- ===========================================================================
-- SECTION 9: dbt-specific Patterns with Comments
-- ===========================================================================
-- 9.1: is_incremental() with comments
{# incremental model pattern #} {{ config(materialized='incremental', unique_key='id') }}
/* config */ SELECT /* sel */ * /* star */ 
FROM /* from */ {{ source('raw', 'events') }} /* source ref */ {% if is_incremental() %}
WHERE /* incremental check */ {# only new records #} /* where */ event_time /* col */ > /* gt */ ( /* o1 */ SELECT /* sub sel */ MAX /* agg */ ( /* o2 */ event_time /* col */ ) /* c2 */ 
FROM /* from */ {{ this }} /* self ref */ ) /* c1 */ {% endif %} /* endif incr */ ;
-- 9.2: var() with default and comments
{# configurable date range #} SELECT /* sel */ * /* star */ 
FROM /* from */ {{ ref('fct_orders') }}
/* ref */ WHERE /* where */ order_date /* col */ >= /* ge */ '{{ var("start_date", "2024-01-01") }}' /* start var */ AND /* and */ order_date /* col2 */ <= /* le */ '{{ var("end_date", "2024-12-31") }}' /* end var */ ;
-- 9.3: run_query with comments
{# dynamic column discovery #} {% set results = run_query("SELECT column_name FROM information_schema.columns WHERE table_name = 'orders'") %}
/* query */ {% if execute %}
/* execute check */ {# only during execution #} {% set columns = results.columns[0].values() %}
/* extract cols */ {% endif %}
/* endif */ SELECT /* sel */ {% for col in columns %}
    /* col loop */ {{ col }} /* col var */ {% if not loop.last %} /* comma? */ , /* sep */ {% endif %}
{% endfor %}
/* endfor */ FROM /* from */ orders /* tbl */ ;
-- 9.4: log() and exceptions with comments
{# debugging and validation #} {% if var('debug_mode', false) %}
/* debug check */ {{ log("Running in debug mode for table: " ~ this, info=true) }}
/* log call */ {% endif %}
/* endif debug */ {% if not var('skip_validation', false) %}
/* validation check */ {# validate required variable #} {% if not var('required_param', none) %}
/* param check */ {{ exceptions.raise_compiler_error("required_param must be set!") }}
/* raise error */ {% endif %}
/* endif param */ {% endif %}
/* endif validation */ SELECT /* sel */ 1 /* lit */ ;
-- ===========================================================================
-- SECTION 10: Complex Real-World Patterns with Comments
-- ===========================================================================
-- 10.1: Staging model pattern with comments
{# staging model for raw orders #} {{ config(materialized='view') }}
/* view config */ WITH /* cte kw */ 
    source /* cte name */ AS /* as */ ( /* open cte */ 
        {# raw data from source #} SELECT /* sel */ * /* star */ 
        FROM /* from */ {{ source('raw_database', 'raw_orders') }}
    /* source */ ) /* close cte */ , /* comma */ 
    renamed /* cte2 name */ AS /* as2 */ ( /* open cte2 */ 
        {# rename columns to standard names #} SELECT /* sel */ 
            /* primary key */ id /* id col */ AS /* as */ order_id /* alias */ ,
            /* foreign key */ cust_id /* fk col */ AS /* as2 */ customer_id /* alias2 */ ,
            /* business columns */ ord_date /* biz col */ AS /* as3 */ order_date /* alias3 */ ,
            ord_total /* biz col2 */ AS /* as4 */ order_total /* alias4 */ ,
            /* metadata */ _loaded_at /* meta col */ AS /* as5 */ loaded_at /* alias5 */ 
        FROM /* from */ source /* cte ref */ 
    ) /* close cte2 */ 
SELECT /* final sel */ * /* star */ 
FROM /* from */ renamed /* final ref */ ;
-- 10.2: Incremental merge pattern with comments
{# incremental merge with SCD Type 2 #} {{ config(materialized='incremental', unique_key='surrogate_key', incremental_strategy='merge') }}
/* config */ {% if is_incremental() %}
/* incr check */ {# incremental load #} SELECT /* sel */ 
    {{ dbt_utils.generate_surrogate_key(['id', 'effective_date']) }} /* sk */ AS /* as */ surrogate_key /* alias */ ,
    * /* star */ ,
    CURRENT_TIMESTAMP /* fn */ ( /* o */ ) /* c */ AS /* as2 */ updated_at /* alias2 */ 
FROM /* from */ {{ ref('stg_products') }}
/* stg ref */ WHERE /* where */ updated_at /* col */ > /* gt */ ( /* o1 */ SELECT /* sub */ MAX /* agg */ ( /* o2 */ updated_at /* col2 */ ) /* c2 */ 
FROM /* from2 */ {{ this }} /* self */ ) /* c1 */ 
{% else %}
/* full load */ {# initial full load #} SELECT /* sel */ 
    {{ dbt_utils.generate_surrogate_key(['id', 'effective_date']) }} /* sk2 */ AS /* as3 */ surrogate_key /* alias3 */ ,
    * /* star2 */ ,
    CURRENT_TIMESTAMP /* fn2 */ ( /* o3 */ ) /* c3 */ AS /* as4 */ updated_at /* alias4 */ 
FROM /* from3 */ {{ ref('stg_products') }}
/* stg ref2 */ {% endif %} /* endif */ ;
-- 10.3: Macro call with complex parameters and comments
{# dynamic pivot #} SELECT /* sel */ id /* id col */ , {{ dbt_utils.pivot(column='category', values=['A', 'B', 'C'], agg='SUM', then_value='amount') }}
/* pivot call */ FROM /* from */ transactions /* tbl */ 
GROUP /* group */ BY /* by */ id /* grp col */ ;
-- 10.4: Documentation block with comments
{# model documentation #} {% docs orders_model %} /* docs block */
This model contains order data.
-- This is NOT a SQL comment, it's in docs
/* This is also NOT a SQL comment */
{# This Jinja comment is inside docs which is interesting #}
{% enddocs %}
/* end docs */ 
-- 10.5: Complex CTE with multiple Jinja blocks and comments
{# complex analytical query #} {{ config(materialized='table', sort='order_date', dist='customer_id') }}
/* config */ WITH /* cte start */ 
    {# base data CTE #} base_data /* cte1 */ AS /* as1 */ ( /* o1 */ 
        SELECT /* sel1 */ * /* star1 */ 
        FROM /* from1 */ {{ ref('stg_orders') }} /* ref1 */ {% if is_incremental() %}
        WHERE /* incr1 */ /* where1 */ order_date /* col1 */ > /* gt1 */ ( /* o2 */ SELECT /* sub1 */ MAX /* agg1 */ ( /* o3 */ order_date /* col2 */ ) /* c3 */ 
        FROM /* from2 */ {{ this }} /* self1 */ ) /* c2 */ {% endif %}
    /* end incr1 */ ) /* c1 */ , /* comma1 */ 
    {# enrichment CTE #} enriched /* cte2 */ AS /* as2 */ ( /* o4 */ 
        SELECT /* sel2 */ 
            b /* alias1 */ . /* d1 */ * /* star2 */ ,
            c /* alias2 */ . /* d2 */ customer_name /* col3 */ ,
            {% for metric in ['quantity', 'discount', 'tax'] %}
                /* metric loop */ b /* alias3 */ . /* d3 */ {{ metric }} /* metric col */ AS /* as3 */ order_
                {{ metric }} /* metric alias */ {% if not loop.last %} /* comma check */ , /* sep */ {% endif %}
            {% endfor %}
        /* end metric loop */ FROM /* from3 */ 
        base_data /* base ref */ b /* b alias */ 
        LEFT /* left */ JOIN /* join */ {{ ref('dim_customers') }} /* dim ref */ c /* c alias */ ON /* on */ b /* b a */ . /* d4 */ customer_id /* col4 */ = /* eq */ c /* c a */ . /* d5 */ id /* col5 */ 
    ) /* c4 */ 
{# final output #} SELECT /* final sel */ * /* final star */ 
FROM /* final from */ enriched /* final ref */ ;
-- ===========================================================================
-- SECTION 11: Edge Cases and Boundary Conditions with Comments
-- ===========================================================================
-- 11.1: Empty Jinja blocks with comments
{# empty for loop #} {% for item in [] %}
/* empty */ {{ item }}
/* never */ {% endfor %}
/* end empty */ SELECT /* sel */ 1 /* lit */ ;
-- 11.2: Jinja with special characters in strings with comments
{# special chars test #} SELECT /* sel */ 
    '{{ "string with 'quotes' and \"double quotes\"" }}' /* quoted */ AS /* as */ quoted_val /* alias */ ,
    '{{ "string with -- SQL comment chars" }}' /* sql chars */ AS /* as2 */ sql_chars /* alias2 */ ,
    '{{ "string with /* block */ chars" }}' /* block chars */ AS /* as3 */ block_chars /* alias3 */ ;
-- 11.3: Deeply nested parentheses with Jinja and comments
{# complex nesting #} SELECT /* sel */ ( /* o1 */ ( /* o2 */ ( /* o3 */ {{ var('deeply_nested') }} /* var */ ) /* c3 */ ) /* c2 */ ) /* c1 */ AS /* as */ nested /* alias */ , COALESCE /* fn */ ( /* o4 */ NULLIF /* fn2 */ ( /* o5 */ {{ col1 }} /* c1 */ , /* sep1 */ '' /* empty */ ) /* c5 */ , /* sep2 */ NULLIF /* fn3 */ ( /* o6 */ {{ col2 }} /* c2 */ , /* sep3 */ '' /* empty2 */ ) /* c6 */ , /* sep4 */ 'default' /* def */ ) /* c4 */ AS /* as2 */ result /* alias2 */ 
FROM /* from */ {{ ref('source') }} /* src */ ;
-- 11.4: Jinja at start/end of expressions with comments
{# expression boundaries #} SELECT /* sel */ 
    {{ prefix }}column_name /* start jinja */ AS /* as */ col1 /* alias1 */ ,
    column_name{{ suffix }} /* end jinja */ AS /* as2 */ col2 /* alias2 */ ,
    {{ full_expression }} /* full jinja */ AS /* as3 */ col3 /* alias3 */ 
FROM /* from */ tbl /* tbl */ ;
-- 11.5: Multiple Jinja expressions in one SQL expression with comments
{# multiple jinja in expr #} SELECT /* sel */ {{ prefix }} /* p1 */ || /* concat1 */ {{ middle }} /* m1 */ || /* concat2 */ {{ suffix }} /* s1 */ AS /* as */ combined /* alias */ , {{ a }} /* a1 */ + /* add */ {{ b }} /* b1 */ * /* mul */ {{ c }} /* c1 */ AS /* as2 */ calc /* alias2 */ 
FROM /* from */ {{ table }} /* tbl */ ;
-- 11.6: Jinja in CASE expression with comments
{# jinja in case #} SELECT /* sel */ CASE /* case */ 
    WHEN /* w1 */ {{ condition1 }} /* cond1 */ THEN /* t1 */ {{ result1 }}
    /* res1 */ WHEN /* w2 */ {{ condition2 }} /* cond2 */ THEN /* t2 */ {{ result2 }}
    /* res2 */ {% for extra in extra_conditions %}
    /* extra loop */ WHEN /* wX */ {{ extra.condition }} /* condX */ THEN /* tX */ {{ extra.result }}
    /* resX */ {% endfor %}
    /* end extra loop */ ELSE /* else */ {{ default_result }}
/* def res */ END /* end */ AS /* as */ computed /* alias */ 
FROM /* from */ {{ source_table }} /* src */ ;
-- ===========================================================================
-- SECTION 12: Statement Boundaries with Jinja and Comments
-- ===========================================================================
-- 12.1: Multiple statements with Jinja between them
{# first statement #} SELECT /* s1 */ 1 /* lit1 */ ;
{# between statements #} /* block between */ 
-- line between
SELECT /* s2 */ 2 /* lit2 */ ;
{# after statements #} 
-- 12.2: Jinja generating multiple statements with comments
{# multi-statement generator #} {% for schema in ['schema1', 'schema2', 'schema3'] %}
/* schema loop */ 
-- Creating view for {{ schema }}
/* view {{ schema }} */ CREATE /* create */ OR /* or */ REPLACE /* replace */ VIEW /* view */ {{ schema }} /* schema */ . /* dot */ summary /* vname */ 
AS /* as */ 
SELECT /* sel */ COUNT /* agg */ ( /* o */ * /* star */ ) /* c */ AS /* as2 */ cnt /* alias */ 
FROM /* from */ {{ schema }} /* schema2 */ . /* dot2 */ data /* tbl */ ;
{% endfor %}
/* end loop */ 
-- 12.3: Jinja control flow spanning statements with comments
{# environment-specific DDL #} {% if create_tables %}
/* create check */ 
-- Creating tables
CREATE /* c1 */ TABLE /* t1 */ IF /* if1 */ NOT /* not1 */ EXISTS /* ex1 */ staging /* tbl1 */ ( /* o1 */ 
    id /* col1 */ INT /* type1 */ 
) /* c1 */ ;
CREATE /* c2 */ TABLE /* t2 */ IF /* if2 */ NOT /* not2 */ EXISTS /* ex2 */ production /* tbl2 */ ( /* o2 */ 
    id /* col2 */ INT /* type2 */ 
) /* c2 */ ;
{% endif %}
/* end create check */ {% if seed_data %}
/* seed check */ 
-- Seeding data
INSERT /* i1 */ INTO /* into1 */ staging /* tbl3 */ 
VALUES /* v1 */ ( /* o3 */ 1 /* val */ ) /* c3 */ ;
{% endif %}
/* end seed check */ 
-- ===========================================================================
-- SECTION 13: Final Comprehensive Test with Everything
-- ===========================================================================
{# Ultimate hostile test combining all features #} 
-- SQL line comment at top
/* SQL block comment at top */ {{ config(
    materialized='incremental',
    unique_key='id',
    schema='analytics'
) }}
/* end config */ {# Set up variables #} {% set table_name = 'orders' %}
/* set1 */ {% set columns = ['id', 'amount', 'status'] %}
/* set2 */ 
-- SQL comment after sets
{# Jinja comment after sets #} WITH /* cte start */ 
    {# first CTE #} base /* cte1 */ AS /* as1 */ ( /* o1 */ 
        /* base selection */ SELECT /* sel1 */ {% for col in columns %}
            /* col loop */ {{ col }} /* col */ {% if not loop.last %} /* comma check */ , /* sep */ {% endif %}
        {% endfor %}
        /* end col loop */ FROM /* from1 */ {{ ref(table_name) }} /* table ref */ {% if is_incremental() %}
        WHERE /* incr check */ {# incremental filter #} /* where1 */ updated_at /* col */ > /* gt */ {{ var('min_date', "'2024-01-01'") }} /* date var */ {% endif %}
    /* end incr */ ) /* close cte1 */ , /* comma */ 
    {# second CTE with conditional logic #} filtered /* cte2 */ AS /* as2 */ ( /* o2 */ 
        SELECT /* sel2 */ * /* star */ 
        FROM /* from2 */ base /* base ref */ 
        WHERE /* where2 */ 1 /* lit */ = /* eq */ 1 /* lit2 */ {% if var('status_filter', none) %} /* status check */ /* and1 */ AND status /* col */ = /* eq2 */ '{{ var("status_filter") }}' /* status var */ {% endif %} /* end status */ {% if var('min_amount', none) %} /* amount check */ /* and2 */ AND amount /* col2 */ >= /* ge */ {{ var('min_amount') }} /* amount var */ {% endif %}
    /* end amount */ ) /* close cte2 */ 
{# final selection #} 
-- final output
/* selecting from filtered */ SELECT /* final sel */ 
    {% if group_by_status %}
        /* group check */ status /* grp col */ ,
        COUNT /* agg */ ( /* o3 */ * /* star2 */ ) /* c3 */ AS /* as3 */ cnt /* cnt alias */ ,
        SUM /* agg2 */ ( /* o4 */ amount /* amt col */ ) /* c4 */ AS /* as4 */ total /* tot alias */ 
    {% else %}
        /* no grouping */ * /* star3 */ 
    {% endif %}
/* end group check */ FROM /* final from */ filtered /* filtered ref */ 
{% if group_by_status %}
/* group clause check */ GROUP /* group */ BY /* by */ status /* grp col */ {% endif %}
/* end group clause */ ORDER /* order */ BY /* by */ 
{% if order_by_col %}
    /* order check */ {{ order_by_col }} /* order col */ {{ order_direction }} /* order dir */
    {% else %}
    /* default order */ id /* default col */ 
{% endif %}
/* end order check */ {% if limit_results %}
    /* limit check */ LIMIT /* limit */ {{ limit_results }} /* limit var */
{% endif %} /* end limit */ ;
-- End of hostile Jinja test file
/* Final block comment */ {# Final Jinja comment #} 