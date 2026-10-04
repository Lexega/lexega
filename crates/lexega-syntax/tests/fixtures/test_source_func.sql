SELECT *
FROM {{ source('raw', 'events') }} AS e;