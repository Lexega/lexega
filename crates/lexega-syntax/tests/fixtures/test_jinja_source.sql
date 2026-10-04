SELECT *
FROM {{ source('raw', 'customers') }}