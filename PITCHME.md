---?image=assets/img/glasgow.png&position=left&size=55% 100%
@title[Talking Security]

# Talking... Security @fa[lock]

Note: 

- Welcome all
- This is a small talk about security
- Tries to be general (About security), but specific (about our case)

---

## Agenda

- Verification & Validaton
- Context & Codification
- Web problems

---
## Verification

- Normally it refers to the act of contrasting what was implemented with the requirements.
- In Security, is the act of controlling that input(s) are correct semantically

+++
@title[It this being verified?]

```perl
sub _get_segment_data {
  my ( $self, $db ) = @_;

  $db = $self->{ app_id } unless $db;
  my $dbprefix = $self->{ app_id } eq $db ? "" : "$db.";

  my ( $sql_query, $disp_query );
  if ( my $seg = $self->param( "segment" ) ) {
    $sql_query  = sprintf( "( %s )", $seg );
    if ( $self->param( "segment_description" ) ) {
      $disp_query = $self->param( "segment_description" );
    }
    else {
      $disp_query = $seg;
      $disp_query =~ s/([\d_]+\s*=\s*[\'\"\d]+)/$self->_get_human_segment_desc($1)/eg;
    }
  }
  else {
    local $self->{ never_use_ro_dbh } = 1;
    my $cached = $self->_cache(
      sprintf( "%s:segments:%s", $db, $self->{ sid } ),
      sub {
        my @segment = $self->_get_first_row(
          $self->_sql_select(
            qq{
SELECT sql_query, disp_query
  FROM ${dbprefix}segments
 WHERE username = ? AND sid = ?},
            $self->{ username }, $self->{ sid }
          )
        );
        return \@segment;
      },
      3600
    );
    ( $sql_query, $disp_query ) = @$cached;
  }

  if ( $sql_query ) {
    $sql_query =~ s/^\s+//g;
    $sql_query =~ s/\s+$//g;
  }

  $self->{ addl_where_text } = $sql_query;
  $self->{ disp_query      } = $disp_query;
  $self->{ disp_query_text } = $disp_query;

  # Make the "search" menu persist
  $self->_create_search_menu() if $self->_is_html_req();

  return ( $sql_query, $disp_query );
}
```

@[1-2](Well know funcdion)
@[8-9](That takes parameters from outside)
@[40-44](And lucky for us.... wipes all spaces at the beggining and end)

+++
### Do we have a TCB?

- Who do we trust?(tm)
- The OS? The data in the database?

+++
### Typing
- In the end there is a typing problem
- All the web is a `string`
- But we have different types in our code, and in our DB
- And what about codifications?

+++
### Sanitize all inputs

- All inputs must be sanitized
- The resposibility relies on the `sub` that receives the data (this is easier when using MVC)

---
### Validation

- Is the act of dinamycally execute and test a program, so it conforms with the actual requirements.
- Do you remember, we already did verification!

- Once we have valid type for our data, is it valid in our context?
- If it is some ID, it is valid and the user can access it?

---
## Context and Codification

- Codification depends on context.
- You cannot codify output as HTML, if you are outputting JS
- Sanitization will depend on context also (see for example Taint mode)
