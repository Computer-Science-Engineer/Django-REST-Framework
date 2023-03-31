# Generated by Django 4.1.5 on 2023-03-07 04:35

from django.db import migrations, models
import djongo.models.fields


class Migration(migrations.Migration):

    dependencies = [
        ('TESappnew', '0013_remove_tes_template_model_template_id'),
    ]

    operations = [
        migrations.CreateModel(
            name='TES_report_model',
            fields=[
                ('id', djongo.models.fields.ObjectIdField(auto_created=True, db_column='_id', primary_key=True, serialize=False)),
                ('report_name', models.CharField(max_length=100)),
                ('template_id', models.CharField(max_length=100)),
            ],
            options={
                'verbose_name_plural': 'reports',
                'db_table': 'reports',
            },
        ),
    ]
