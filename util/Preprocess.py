import pandas as pd
import pyarrow
import re
import json

#SQLi
def csv_2_parquet(csv_path, par_name):
    df = pd.read_csv(csv_path,sep=',')
    par_name = 'dataset\\Unprocessed\\SQL-Injection\\'+ par_name + '.parquet'
    df.to_parquet(par_name, engine="pyarrow", compression="snappy")

def extract_SQL_features(df):
    features = []

    for query in df['Query']:
        query_features = []
    
        # 1. Query Length
        query_features.append(len(query))
        
        # 2. Number of Words
        query_features.append(len(query.split()))
        
        # 3. Number of Special Characters
        special_chars = re.findall(r'[\!@#$%^&*()_+=\-<>?/\|\\:;"\'{}[\]]', query)
        query_features.append(len(special_chars))
        
        # 4. Number of SQL Keywords
        sql_keywords = ['select', 'insert', 'update', 'delete', 'drop', 'union', 'exist', 'where', 'and', 'or', 'from', 'create']
        keyword_count = sum([query.lower().count(keyword) for keyword in sql_keywords])
        query_features.append(keyword_count)
        
        # 5. Presence of 'UNION'
        query_features.append(int('union' in query.lower()))
        
        # 6. Presence of 'SELECT'
        query_features.append(int('select' in query.lower()))
        
        # 7. Presence of 'FROM'
        query_features.append(int('from' in query.lower()))
        
        # 8. Presence of 'OR'
        query_features.append(int('or' in query.lower()))
        
        # 9. Presence of 'AND'
        query_features.append(int('and' in query.lower()))
        
        # 10. Presence of 'INSERT'
        query_features.append(int('insert' in query.lower()))
        
        # 11. Presence of 'DROP'
        query_features.append(int('drop' in query.lower()))
        
        # 12. Presence of 'TABLE'
        query_features.append(int('table' in query.lower()))
        
        # 13. Presence of 'WHERE'
        query_features.append(int('where' in query.lower()))
        
        # 14. Presence of 'GROUP BY'
        query_features.append(int('group by' in query.lower()))
        
        # 15. Presence of 'HAVING'
        query_features.append(int('having' in query.lower()))
        
        # 16. Presence of 'LIMIT'
        query_features.append(int('limit' in query.lower()))
        
        # 17. Presence of 'ORDER BY'
        query_features.append(int('order by' in query.lower()))
        
        # 18. Number of Parentheses
        query_features.append(query.count('(') + query.count(')'))
        
        # 19. Presence of '/*'
        query_features.append(int('/*' in query))
        
        # 20. Presence of '--'
        query_features.append(int('--' in query))
        
        # 21. Presence of 'sleep'
        query_features.append(int('sleep' in query.lower()))
        
        # 22. Presence of 'load_file'
        query_features.append(int('load_file' in query.lower()))
        
        # 23. Presence of 'subselect'
        query_features.append(int('select' in query.lower() and '(' in query))
        
        # 24. Presence of 'ASCII'
        query_features.append(int('ascii' in query.lower()))
        
        # 25. Presence of 'database'
        query_features.append(int('database' in query.lower()))
        
        # 26. Number of = 1
        query_features.append(query.count('= 1'))
        
        # 27. Number of Comments
        query_features.append(query.count('--') + query.count('/*'))
        
        # 28. Number of Subqueries
        query_features.append(query.count('select') - query.count('union'))
        
        # 29. Presence of 'version'
        query_features.append(int('version' in query.lower()))
        
        # 30. Presence of 'information_schema'
        query_features.append(int('information_schema' in query.lower()))
        
        # 31. Use of 'sleep' with time
        query_features.append(int('sleep' in query.lower() and 'time' in query.lower()))
        
        # 32. Presence of 'hex' encoded values
        query_features.append(int('hex' in query.lower()))
        
        # 33. Presence of 'ASCII' operations
        query_features.append(int('ascii' in query.lower()))
        
        # 34. Presence of SQL functions (e.g., 'substring', 'top', etc.)
        sql_functions = ['substring', 'top', 'concat', 'left', 'right']
        query_features.append(int(any(func in query.lower() for func in sql_functions)))
        
        # 35. Presence of 'user'
        query_features.append(int('user' in query.lower()))
        
        # 36. Presence of 'password'
        query_features.append(int('password' in query.lower()))
        
        # 37. Number of '1' literals
        query_features.append(query.count('1'))
        
        # 38. Number of LIKE clauses
        query_features.append(query.lower().count('like'))
        
        # 39. Presence of 'char' function
        query_features.append(int('char(' in query.lower()))
        
        # 40. Presence of 'limit' with numbers
        query_features.append(int('limit' in query.lower() and any(c.isdigit() for c in query)))
        
        # 41. Query Contains null Union Clauses
        query_features.append(int('null' in query.lower()))
        
        # 42. Number of null
        query_features.append(query.lower().count('null'))
        
        # 43. Number of WHERE conditions
        query_features.append(query.lower().count('where'))
        
        # 44. Presence of boolean logic ('= 1' or 'OR 1=1')
        query_features.append(int('= 1' in query.lower() or 'or 1=1' in query.lower()))
        
        # 45. Number of variable assignments
        query_features.append(query.count('@'))
        
        # 46. Presence of system functions (@@version, sys.objects, etc.)
        system_functions = ['@@version', 'sys.objects']
        query_features.append(int(any(func in query.lower() for func in system_functions)))
        
        # 47. Presence of 'delete' delay functions
        query_features.append(int('delete' in query.lower()))
        
        # 48. Number of errors
        query_features.append(int('error' in query.lower()))
        
        # 49. Number of common attack phrases
        attack_phrases = ['or 1=1', 'union select', 'drop table']
        query_features.append(sum(query.lower().count(phrase) for phrase in attack_phrases))
        
        # 50. Presence of known attack patterns
        known_attack_patterns = ['--', '/*', 'select * from', 'union', 'drop']
        query_features.append(int(any(pattern in query.lower() for pattern in known_attack_patterns)))

        features.append(query_features)

    feature_names = ['Query Length', 'Number of Words', 'Number of Special Characters', 'Number of SQL Keywords', 'Presence of UNION', 
                 'Presence of SELECT', 'Presence of FROM', 'Presence of OR', 'Presence of AND', 'Presence of INSERT', 
                 'Presence of DROP', 'Presence of TABLE', 'Presence of WHERE', 'Presence of GROUP BY', 'Presence of HAVING', 
                 'Presence of LIMIT', 'Presence of ORDER BY', 'Number of Parentheses', 'Presence of /*', 'Presence of --', 
                 'Presence of sleep', 'Presence of load_file', 'Presence of subselect', 'Presence of ASCII', 'Presence of database', 
                 'Number of = 1', 'Number of Comments', 'Number of Subqueries', 'Presence of version', 'Presence of information_schema', 
                 'Use of sleep with time', 'Presence of hex encoded values', 'Presence of ASCII operations', 'Presence of SQL functions', 
                 'Presence of user', 'Presence of password', 'Number of 1 literals', 'Number of LIKE clauses', 'Presence of char function', 
                 'Presence of limit with numbers', 'Presence of Null', 'Number of null', 'Number of WHERE conditions', 
                 'Presence of boolean logic', 'Number of variable assignments', 'Presence of system functions', 'Presence of delete', 
                 'Number of errors', 'Number of common attack phrases', 'Presence of known attack patterns']
    
    return pd.concat([df[['Query']], pd.DataFrame(features, columns=feature_names), df[['label']]], axis=1) 

def save_parquet(df, par_name):
    par_name = 'dataset/Processed/' + par_name + '.parquet'
    df.to_parquet(par_name)

#NoSQLi
def json_2_parquet(json_path, par_name):
    df = pd.read_json(json_path)
    par_name = 'dataset\\Unprocessed\\NoSQL-Injection\\' + par_name + '.parquet'
    df.to_parquet(par_name, engine="pyarrow", compression="snappy")

def extract_NoSQL_feature(df):
    feature = []
    
    for query in df['text']:
        query_features = []
        
        # 1. Query Length
        query_features.append(len(query))
        
        # 2. Number of Words
        query_features.append(len(query.split()))
        
        # 3. Number of Special Characters
        special_chars = re.findall(r'[\!@#$%^&*()_+=\-<>?/\|\\:;"\'{}[\]]', query)
        query_features.append(len(special_chars))
        
        # 4. Number of NoSQL Keywords
        nosql_keywords = ['$regex', '$ne', '$gt', '$lt', '$in', '$or', '$and', '$where', '$exists', '$mod']
        keyword_count = sum([query.lower().count(keyword) for keyword in nosql_keywords])
        query_features.append(keyword_count)
        
        # 5. Presence of '$regex'
        query_features.append(int('$regex' in query.lower()))
        
        # 6. Presence of '$ne'
        query_features.append(int('$ne' in query.lower()))
        
        # 7. Presence of '$gt'
        query_features.append(int('$gt' in query.lower()))
        
        # 8. Presence of '$lt'
        query_features.append(int('$lt' in query.lower()))
        
        # 9. Presence of '$in'
        query_features.append(int('$in' in query.lower()))
        
        # 10. Presence of '$or'
        query_features.append(int('$or' in query.lower()))
        
        # 11. Presence of '$and'
        query_features.append(int('$and' in query.lower()))
        
        # 12. Presence of '$where'
        query_features.append(int('$where' in query.lower()))
        
        # 13. Presence of '$exists'
        query_features.append(int('$exists' in query.lower()))
        
        # 14. Presence of '$mod'
        query_features.append(int('$mod' in query.lower()))
        
        # 15. Presence of '$all'
        query_features.append(int('$all' in query.lower()))
        
        # 16. Presence of 'admin' keyword
        query_features.append(int('admin' in query.lower()))
        
        # 17. Presence of 'password' keyword
        query_features.append(int('password' in query.lower()))
        
        # 18. Presence of suspicious usernames (e.g., 'root', 'guest')
        suspicious_usernames = ['root', 'guest', 'testuser', 'admin']
        query_features.append(int(any(user in query.lower() for user in suspicious_usernames)))
        
        # 19. Presence of 'remove' condition
        query_features.append(int('remove' in query.lower()))
        
        # 20. Number Presence of '$or' and '$and' logical operator
        query_lower = query.lower()
        query_features.append(query_lower.count('$or') + query_lower.count('$and'))
        
        # 21. Number of Nested Conditions within $or or $and
        nested_conditions_count = len(re.findall(r'(\$or|\$and)\s*:\s*\[.*\{', query))
        query_features.append(nested_conditions_count)
        
        # 22. Number of $or conditions
        query_features.append(query.lower().count('$or'))
        
        # 23. Number of $and conditions
        query_features.append(query.lower().count('$and'))
        
        # 24. Number of $regex conditions
        query_features.append(query.lower().count('$regex'))
        
        # 25. Presence of SQL-like keywords (e.g., 'union', 'select')
        nosql_injections = ['union', 'select', 'drop', 'insert', 'delete']
        query_features.append(int(any(keyword in query.lower() for keyword in nosql_injections)))
        
        # 26. Number of Nested Functions (e.g., $mod in $or)
        nested_functions_count = len(re.findall(r'(\$mod|$eq|$in)\s*:\s*\[.*\{', query))
        query_features.append(nested_functions_count)
        
        # 27. Presence of dynamic query components (e.g., user input)
        query_features.append(int('req.query' in query or 'req.params' in query))
        
        # 28. Presence of $size
        query_features.append(int('$size' in query.lower()))
        
        # 29. Presence of sleep function (common in DoS or timed attacks)
        query_features.append(int('sleep' in query.lower()))
        
        # 30. Presence of 'insert()' function
        query_features.append(int('insert(' in query))
        
        # 31. Number of occurrences of the word 'user'
        query_features.append(query.lower().count('user'))
        
        # 32. Number of occurrences of the word 'password'
        query_features.append(query.lower().count('password'))
        
        # 33. Presence of non-ASCII characters (could indicate obfuscation)
        query_features.append(int(any(ord(c) > 127 for c in query)))
        
        # 34. Presence of encoded characters (e.g., URL encoding)
        query_features.append(int('%' in query))
        
        # 35. Number of 'or 1=1' or similar attack patterns
        query_features.append(int('or 1=1' in query.lower() or 'or 1=0' in query.lower()))
        
        # 36. Presence of SQL injection-like patterns in query
        query_features.append(int('drop' in query.lower() or 'select' in query.lower()))
        
        # 37. Presence of $type
        query_features.append(int('$type' in query.lower()))
  
        # 38. Presence of function calls like 'eval', 'match', 'insert'
        query_features.append(int('eval(' in query or 'match(' in query or 'insert(' in query))
        
        # 39. Presence of 'dropDatabase' function call
        query_features.append(int('dropDatabase' in query.lower()))
        
        # 40. Presence of suspicious SQL-like patterns (e.g., 'select * from', 'drop table')
        query_features.append(int(any(pattern in query.lower() for pattern in ['select * from', 'drop table'])))
        
        # 41. Presence of illegal operators (e.g., '$where', '$gt' without parameters)
        query_features.append(int('$where' in query.lower() and not re.search(r'\{.*\}', query)))
        
        # 42. Number of suspicious characters (e.g., quotes, semicolons)
        query_features.append(sum(1 for char in query if char in [';', "'", '"']))
        
        # 43. Presence of invalid or incomplete query structures
        query_features.append(int('null' in query.lower()))
        
        # 44. Presence of specific user-related values (e.g., 'admin', 'root')
        query_features.append(int('admin' in query.lower() or 'root' in query.lower()))
        
        # 45. Presence of 'get()' function for data retrieval
        query_features.append(int('get(' in query))
        
        # 46. Presence of 'createIndex()' function
        query_features.append(int('createIndex' in query.lower()))
        
        # 47. Presence of 'insertMany()' function
        query_features.append(int('insertMany' in query.lower()))

        # 48. Presence of $option
        query_features.append(int('$option' in query.lower()))

        # 49. Presence of $nin
        query_features.append(int('$nin' in query.lower()))

        # 50. Presence of $not
        query_features.append(int('$not' in query.lower()))

        # 51. Presence of $set
        query_features.append(int('$set' in query.lower()))
        
        # 52. Presence of $gte
        query_features.append(int('$gte' in query.lower()))
        
        feature.append(query_features)

    feature_names = ['Query Length', 'Number of Words',  'Number of Special Characters',  'Number of NoSQL Keywords',  'Presence of $regex', 'Presence of $ne', 'Presence of $gt', 'Presence of $lt', 'Presence of $in', 'Presence of $or', 'Presence of $and','Presence of $where', 'Presence of $exists', 'Presence of $mod', 'Presence of $all', 'Presence of admin', 'Presence of password', 'Suspicious Usernames', 'Presence of remove', 'Number Presence of \'$or\' and \'$and\' logical operator', 'Number of Nested Conditions within $or or $and', 'Number of $or conditions', 'Number of $and conditions', 'Number of $regex conditions', 'Presence of SQL Injections', 'Number of Nested Functions', 'Presence of dynamic query components', 'Presence of $size', 'Presence of sleep', 'Presence of insert() function', 'Number of user occurrences', 'Number of password occurrences', 'Presence of non-ASCII characters', 'Presence of encoded characters', 'Number of or 1=1 occurrences', 'Presence of SQL injection-like patterns', 'Presence of Presence of $type', 'Presence of function calls EMI', 'Presence of dropDatabase', 'Presence of suspicious SQL patterns', 'Presence of illegal operators', 'Number of suspicious characters', 'Presence of incomplete query structures', 'Presence of specific user values', 'Presence of get() function', 'Presence of createIndex() function', 'Presence of insertMany() function','Presence of $option','Presence of $nin','Presence of $not','Presence of $set','Presence of $gte']

    return pd.concat([df[['text']], pd.DataFrame(feature, columns=feature_names), df[['label']]], axis=1)
    
#SQLi
csv_2_parquet('dataset\\Unprocessed\\SQL-Injection\\Modified_SQL_Dataset.csv','SQLi')
df = pd.read_parquet('dataset\\Unprocessed\\SQL-Injection\\SQLi.parquet')
df = extract_SQL_features(df)
print(df.shape)
# save_parquet(df, 'SQLi_feature')

#NoSQLi
# json_2_parquet('dataset\\Unprocessed\\NoSQL-Injection\\No-SqlDataset.json','NoSQLi')
# df = pd.read_parquet('dataset\\Unprocessed\\NoSQL-Injection\\NoSQLi.parquet')
# df = extract_NoSQL_feature(df)
# save_parquet(df, 'NoSQLi_feature')